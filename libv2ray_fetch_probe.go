package libv2ray

// ECH bootstrap by probing the target server directly, with no DNS lookup.
//
// Per draft-ietf-tls-esni section 6.1.6 a server that cannot decrypt an ECH
// payload does not fail the handshake: it completes against the ClientHelloOuter,
// presents a certificate for the public name, and returns its current keys in
// the retry_configs field of EncryptedExtensions. Offering a deliberately
// undecryptable config therefore hands us the server's real keys.
//
// This mirrors xray-core's transport/internet/tls/ech_probe.go, whose helpers
// are unexported. The difference that matters: xray probes through
// internet.DialSystem, which on Android is the ProtectedDialer, so it would
// ignore this call's proxy, ip and fragment settings and leave the device by a
// different path than the request it is bootstrapping. This dials through
// rawDial instead, so the probe takes exactly the same route as the request.

import (
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"

	xtls "github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

const (
	echProbeScheme = "probe"
	// Cloudflare uses one fleet-wide public name: every ECH-enabled zone behind
	// it advertises the same one, so it is the sensible default target.
	echProbeDefaultName = "cloudflare-ech.com"
	echProbeDefaultPort = "443"
	// A probed config carries no DNS TTL, so pick one. Cloudflare rotates the
	// advertised key roughly hourly and retires old keys on a staggered,
	// per-datacenter schedule, so 30 minutes keeps a margin inside that window.
	// Same value xray uses.
	echProbeTTL     uint32 = 1800
	echProbeTimeout        = 12 * time.Second

	// draft-ietf-tls-esni-13 and later
	echConfigVersion uint16 = 0xfe0d
	// DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM
	echKemX25519    uint16 = 0x0020
	echKdfSHA256    uint16 = 0x0001
	echAeadAES128   uint16 = 0x0001
	echX25519KeyLen        = 32
)

// parseECHProbe reads a probe spec. Every spelling xray's echConfigList accepts
// works here, so a value can be copied straight out of an xray config:
//
//	probe                           -> name cloudflare-ech.com, dial cloudflare-ech.com:443
//	probe://                        -> same
//	probe://example.com             -> name example.com,        dial example.com:443
//	probe://example.com@1.2.3.4:443 -> name example.com,        dial 1.2.3.4:443
//
// The scheme may also be omitted, since our own JSON key already says "probe":
//
//	example.com@1.2.3.4             -> name example.com,        dial 1.2.3.4:443
func parseECHProbe(s string) (publicName string, hostPort string, err error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.EqualFold(s, echProbeScheme):
		s = ""
	case strings.HasPrefix(strings.ToLower(s), echProbeScheme+"://"):
		s = strings.TrimSpace(s[len(echProbeScheme)+len("://"):])
	}

	// Split the optional dial target off the right. A public name therefore may
	// not contain '@', which is fine: it has to be a DNS name.
	if at := strings.LastIndex(s, "@"); at >= 0 {
		hostPort = strings.TrimSpace(s[at+1:])
		s = strings.TrimSpace(s[:at])
	}

	publicName = echProbeDefaultName
	if s != "" {
		publicName = s
	}
	if strings.ContainsAny(publicName, ":/ ") {
		return "", "", fmt.Errorf("ECH probe public name %q must be a bare domain", publicName)
	}
	if l := len(publicName); l == 0 || l > 255 {
		return "", "", fmt.Errorf("ECH probe public name has invalid length: %d", l)
	}

	if hostPort == "" {
		hostPort = net.JoinHostPort(publicName, echProbeDefaultPort)
	} else if _, _, splitErr := net.SplitHostPort(hostPort); splitErr != nil {
		// address given without a port
		hostPort = net.JoinHostPort(hostPort, echProbeDefaultPort)
	}
	return publicName, hostPort, nil
}

// bogusECHConfigList builds a structurally valid ECHConfigList whose HPKE key is
// random, so the server can never decrypt a payload sealed to it. On the wire
// this is shaped like the GREASE ECH Chrome sends on every connection, so it
// introduces no new fingerprint.
func bogusECHConfigList(publicName string) ([]byte, error) {
	if l := len(publicName); l == 0 || l > 255 {
		return nil, fmt.Errorf("ECH probe public name has invalid length: %d", l)
	}
	key := make([]byte, echX25519KeyLen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	var configID [1]byte
	if _, err := io.ReadFull(rand.Reader, configID[:]); err != nil {
		return nil, err
	}

	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		list.AddUint16(echConfigVersion)
		list.AddUint16LengthPrefixed(func(cfg *cryptobyte.Builder) {
			cfg.AddUint8(configID[0])
			cfg.AddUint16(echKemX25519)
			cfg.AddUint16LengthPrefixed(func(pk *cryptobyte.Builder) { pk.AddBytes(key) })
			cfg.AddUint16LengthPrefixed(func(cs *cryptobyte.Builder) {
				cs.AddUint16(echKdfSHA256)
				cs.AddUint16(echAeadAES128)
			})
			cfg.AddUint8(0) // maximum_name_length
			cfg.AddUint8LengthPrefixed(func(n *cryptobyte.Builder) { n.AddBytes([]byte(publicName)) })
			cfg.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {}) // extensions
		})
	})
	return b.Bytes()
}

// looksLikeECHConfigList applies the framing checks the TLS stack performs while
// parsing. A retry_configs value that fails them is rejected here so we fail
// closed rather than caching junk that would break every later handshake.
func looksLikeECHConfigList(b []byte) bool {
	if len(b) < 2 || int(binary.BigEndian.Uint16(b[:2])) != len(b)-2 {
		return false
	}
	configs := 0
	for s := b[2:]; len(s) > 0; configs++ {
		if len(s) < 4 {
			return false
		}
		length := int(binary.BigEndian.Uint16(s[2:4]))
		if len(s) < 4+length {
			return false
		}
		s = s[4+length:]
	}
	return configs > 0
}

// echProbe opens one throwaway TLS connection offering a bogus ECH config and
// returns the retry_configs the server hands back, plus a TTL to cache them for.
//
// The result is authenticated: retry_configs arrive inside a handshake whose
// certificate is validated against publicName, so an attacker who cannot obtain
// that certificate cannot feed us a key. That makes this no weaker than DoH and
// strictly stronger than a plaintext udp:// lookup.
//
// allowInsecure drops that check, for a self-hosted ECH server with a
// self-signed certificate. It makes the probe spoofable — an interceptor can
// hand over a key they own, and the real SNI then gets sealed to it — and is
// honoured only because the caller already opted into allowInsecure.
func (o *transportOptions) echProbe(ctx context.Context, publicName, hostPort string) ([]byte, uint32, error) {
	configList, err := bogusECHConfigList(publicName)
	if err != nil {
		return nil, 0, err
	}

	frag, err := o.fragmentConfig()
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := context.WithTimeout(ctx, echProbeTimeout)
	defer cancel()

	conn, err := o.rawDial(ctx, hostPort, frag)
	if err != nil {
		return nil, 0, fmt.Errorf("ECH probe could not reach %s: %w", hostPort, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// The rejection branch of both stacks ignores InsecureSkipVerify, so these
	// hooks are the only thing that actually relaxes the check there.
	var skipVerify func(utls.ConnectionState) error
	var skipVerifyGo func(gotls.ConnectionState) error
	if o.AllowInsecure {
		skipVerify = func(utls.ConnectionState) error { return nil }
		skipVerifyGo = func(gotls.ConnectionState) error { return nil }
	}

	var retryConfigs []byte
	if o.Fingerprint != "" {
		fp := xtls.GetFingerprint(o.Fingerprint)
		if fp == nil {
			return nil, 0, fmt.Errorf("unknown fingerprint %q", o.Fingerprint)
		}
		uConn := utls.UClient(conn, &utls.Config{
			ServerName: publicName,
			MinVersion: utls.VersionTLS13,
			// The parrot offers these. When ECH is rejected the server picks
			// ALPN from the outer hello, and uTLS rejects a pick we did not
			// advertise.
			NextProtos:                     []string{"h2", "http/1.1"},
			EncryptedClientHelloConfigList: configList,
			// crypto/tls validates the ECH-rejection certificate against the
			// outer public name, as the spec requires. uTLS substitutes
			// config.ServerName (the inner name) there, which cannot match the
			// public name's certificate, so the right name has to be requested
			// explicitly. This is a full WebPKI validation against publicName,
			// not a relaxation.
			InsecureServerNameToVerify:          publicName,
			InsecureSkipVerify:                  o.AllowInsecure,
			EncryptedClientHelloRejectionVerify: skipVerify,
		}, *fp)
		err = uConn.HandshakeContext(ctx)
		var rejected *utls.ECHRejectionError
		if goerrors.As(err, &rejected) {
			retryConfigs, err = rejected.RetryConfigList, nil
		}
	} else {
		// crypto/tls already checks the rejection certificate against the outer
		// public name, so there is nothing to fix up here.
		tlsConn := gotls.Client(conn, &gotls.Config{
			ServerName:                          publicName,
			MinVersion:                          gotls.VersionTLS13,
			NextProtos:                          []string{"h2", "http/1.1"},
			EncryptedClientHelloConfigList:      configList,
			InsecureSkipVerify:                  o.AllowInsecure,
			EncryptedClientHelloRejectionVerify: skipVerifyGo,
		})
		err = tlsConn.HandshakeContext(ctx)
		var rejected *gotls.ECHRejectionError
		if goerrors.As(err, &rejected) {
			retryConfigs, err = rejected.RetryConfigList, nil
		}
	}
	if err != nil {
		return nil, 0, fmt.Errorf("ECH probe to %s as %s failed: %w", hostPort, publicName, err)
	}
	if len(retryConfigs) == 0 {
		return nil, 0, fmt.Errorf("ECH probe to %s returned no retry_configs: %s is probably not ECH-enabled",
			hostPort, publicName)
	}
	if !looksLikeECHConfigList(retryConfigs) {
		return nil, 0, fmt.Errorf("ECH probe to %s returned a malformed ECHConfigList", hostPort)
	}
	return retryConfigs, echProbeTTL, nil
}
