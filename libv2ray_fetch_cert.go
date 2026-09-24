package libv2ray

// ProbeCert: read the certificate a peer presents, over TCP or over QUIC.
//
// This exists because a MASQUE gateway is identified by what its certificate
// says -- subject CN "masque.cloudflareclient.com", issuer O "Cloudflare, Inc."
// -- and over QUIC there is no way to get at that from the Android side: Java
// has no QUIC stack, and FetchWeb returns a response, not a certificate.
//
// Two things make this more than a handshake wrapper:
//
//   - The peer is never trusted. Verification is off and the chain is captured
//     from inside the verify callback instead of read from the connection
//     state, so a handshake that FAILS still yields the certificate. That is
//     the normal case here: a gateway asks for a client certificate and hangs
//     up when none arrives, having already sent its own.
//
//   - The QUIC path reuses FetchWeb's machinery -- the wnoise priming, the
//     version ladder, the Chrome parrot -- so a probe leaves the device looking
//     like the connection it is testing for, rather than like a scanner.
//
// No HTTP request is ever sent: the handshake is the whole transaction.

import (
	"context"
	"crypto/sha256"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/GFW-knocker/Xray-core/transport/internet/quicdial"
)

// CertResult is the result of ProbeCert.
//
// A result is useful whenever Leaf is non-empty, error or not: the fields below
// are filled from whatever the peer sent before it stopped talking.
type CertResult struct {
	// Subject and Issuer are the full distinguished names, RFC 2253 style.
	Subject string
	Issuer  string
	// CommonName and IssuerOrg are the two attributes a MASQUE gateway is
	// recognised by, pulled out so the caller does not have to parse a DN.
	CommonName string
	IssuerOrg  string
	// DNSNames are the subjectAltName dNSName entries, comma separated.
	DNSNames string
	// Alpn is what the peer selected. Empty means it echoed none, which is
	// itself a signal -- but only when AlpnKnown is true.
	Alpn      string
	AlpnKnown bool
	// SpkiSha256 is the hex SHA-256 of the SubjectPublicKeyInfo: the value that
	// goes in a pinnedPeerPublicKeySha256.
	SpkiSha256 string
	NotBefore  string // RFC3339
	NotAfter   string // RFC3339
	// Leaf is the leaf certificate in DER, for a caller that wants to parse
	// more than the fields above.
	Leaf []byte
	// ChainLen is how many certificates the peer sent.
	ChainLen int
	// Proto is "h3" when the probe went over QUIC, "tcp" otherwise.
	Proto string
	// HandshakeOK reports whether the handshake completed on this side.
	//
	// It is not a test of whether the peer will carry traffic. Under TLS 1.3 --
	// which QUIC always uses -- the client finishes as soon as it has sent its
	// own Finished, so a server that rejects the client certificate does so
	// after this point and the rejection arrives on the next read. A gateway
	// that asks for a certificate and hangs up therefore still reports true.
	HandshakeOK bool
	RttMs       int
	// RespError is empty when a certificate was obtained. When a certificate
	// was obtained AND the handshake later failed, the failure is reported here
	// with HandshakeOK false and the certificate fields filled.
	RespError string
}

// probeCertOptions is transportOptions plus the address to dial.
//
// Every transport option that makes sense for a bare handshake applies: ip,
// serverName, alpn, timeout, quicVersion, wnoise*, disableChromeParrot,
// fragment and proxy on the TCP path. allowInsecure is ignored -- a probe never
// verifies -- and ech is ignored, because an ECH handshake would return the
// public name's certificate rather than the peer's own.
type probeCertOptions struct {
	transportOptions
	// Address is "host:port". A bare IP is normal here; when it is one and no
	// serverName is given, no SNI is sent, which is what some edges want.
	Address string `json:"address"`
}

// certSink collects the chain from inside the verify callback.
//
// The callback runs on whichever goroutine drives the handshake -- quic-go uses
// its own -- so this is guarded.
type certSink struct {
	mu  sync.Mutex
	der [][]byte
}

func (s *certSink) capture(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.der) == 0 && len(rawCerts) > 0 {
		s.der = rawCerts
	}
	// Never refuse: judging the certificate is the caller's business, and
	// refusing here would lose the connection state the caller may still want.
	return nil
}

func (s *certSink) chain() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.der
}

// ProbeCert performs one handshake and reports the certificate the peer sent.
//
//	{"address":"162.159.198.1:443",
//	 "serverName":"consumer-masque.cloudflareclient.com",
//	 "alpn":"h3", "timeout":6000,
//	 "wnoise":"quicinit", "wnoisecount":"1", "wnoisedelay":"0-2"}
//
// alpn picks the carrier: "h3" goes over QUIC, anything else over TCP. On the
// TCP path the offer is the usual list for that mode, so "h2" offers exactly
// h2 and an edge that echoes it back is distinguishable from one that does not.
func ProbeCert(optionsJSON string) *CertResult {
	opts := &probeCertOptions{}
	if err := json.Unmarshal([]byte(optionsJSON), opts); err != nil {
		return &CertResult{RespError: "invalid options json: " + err.Error()}
	}
	if opts.Address == "" {
		return &CertResult{RespError: "address is required"}
	}
	host, port, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return &CertResult{RespError: fmt.Sprintf("address %q is not host:port: %v", opts.Address, err)}
	}
	if host == "" {
		return &CertResult{RespError: fmt.Sprintf("address %q has no host", opts.Address)}
	}
	if err := opts.validate(); err != nil {
		return &CertResult{RespError: err.Error()}
	}
	mode, err := opts.alpnMode()
	if err != nil {
		return &CertResult{RespError: err.Error()}
	}
	// A pinned ip replaces the host, exactly as it does for a fetch, leaving
	// the name for SNI alone.
	target := net.JoinHostPort(host, port)
	if opts.IP != "" {
		target = net.JoinHostPort(opts.IP, port)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()

	sink := &certSink{}
	tlsConf := opts.certTLSConfig(host, mode)
	tlsConf.VerifyPeerCertificate = sink.capture

	started := time.Now()
	var proto string
	var alpn string
	var handshakeErr error
	if mode == alpnH3 {
		proto = "h3"
		alpn, handshakeErr = opts.handshakeQUIC(ctx, target, tlsConf)
	} else {
		proto = "tcp"
		alpn, handshakeErr = opts.handshakeTCP(ctx, target, tlsConf)
	}
	rtt := int(time.Since(started).Milliseconds())

	chain := sink.chain()
	if len(chain) == 0 {
		msg := "no certificate was presented"
		if handshakeErr != nil {
			msg = handshakeErr.Error()
		}
		return &CertResult{Proto: proto, RttMs: rtt, RespError: msg}
	}

	result := &CertResult{
		Leaf:        chain[0],
		ChainLen:    len(chain),
		Proto:       proto,
		RttMs:       rtt,
		HandshakeOK: handshakeErr == nil,
	}
	if handshakeErr != nil {
		// Not fatal: the certificate is in hand and that is what was asked for.
		// Reported so a caller can tell "it hung up on me" from "it talked".
		result.RespError = handshakeErr.Error()
	} else {
		result.Alpn, result.AlpnKnown = alpn, true
	}

	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		result.RespError = "cannot parse the leaf certificate: " + err.Error()
		return result
	}
	result.Subject = leaf.Subject.String()
	result.Issuer = leaf.Issuer.String()
	result.CommonName = leaf.Subject.CommonName
	if len(leaf.Issuer.Organization) > 0 {
		result.IssuerOrg = leaf.Issuer.Organization[0]
	}
	result.DNSNames = strings.Join(leaf.DNSNames, ",")
	result.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	result.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	if spki, err := x509.MarshalPKIXPublicKey(leaf.PublicKey); err == nil {
		sum := sha256.Sum256(spki)
		result.SpkiSha256 = hex.EncodeToString(sum[:])
	}
	return result
}

// certTLSConfig is tlsConfig without the trust: a probe reads what the peer
// sent and judges it itself, so verification is always off here regardless of
// allowInsecure. ECH is deliberately not carried over -- an accepted ECH
// handshake returns the public name's certificate, not the peer's.
func (o *probeCertOptions) certTLSConfig(host string, mode string) *gotls.Config {
	sni := o.ServerName
	if sni == "" {
		// Same rule as a fetch: fall back to the name dialed. When that is a
		// bare IP, crypto/tls sends no SNI at all, which is what an edge that
		// only answers without one needs.
		sni = host
	}
	return &gotls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         alpnOffer(mode),
	}
}

// handshakeTCP dials, hands over the TLS records, and returns what was
// negotiated. The connection is closed before returning either way.
func (o *probeCertOptions) handshakeTCP(ctx context.Context, target string, cfg *gotls.Config) (string, error) {
	frag, err := o.fragmentConfig()
	if err != nil {
		return "", err
	}
	// rawDial pins o.IP itself; target already carries it, and pinning twice is
	// harmless because the host it replaces is the one already there.
	conn, err := o.rawDial(ctx, target, frag)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	tlsConn := gotls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	return tlsConn.ConnectionState().NegotiatedProtocol, nil
}

// handshakeQUIC opens a socket, primes it with the configured noise, and dials
// the version ladder. Everything it opens is closed before it returns.
func (o *probeCertOptions) handshakeQUIC(ctx context.Context, target string, cfg *gotls.Config) (string, error) {
	attempts, err := o.quicAttempts()
	if err != nil {
		return "", err
	}
	noise, err := o.noiseConfig()
	if err != nil {
		return "", err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return "", fmt.Errorf("h3: cannot resolve %q: %w", target, err)
	}

	pktConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return "", fmt.Errorf("h3: cannot open udp socket: %w", err)
	}
	defer pktConn.Close()

	parrot := !o.DisableChromeParrot
	qTransport := &quic.Transport{Conn: pktConn}
	if parrot {
		qTransport.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}
	defer qTransport.Close()

	quicConfig := &quic.Config{
		Versions:             attempts[0],
		MaxIdleTimeout:       o.timeout(),
		HandshakeIdleTimeout: o.timeout(),
		KeepAlivePeriod:      0,
		ChromeParrot:         parrot,
	}

	// Before the first handshake packet and never after, for the same reason
	// the fetch path does it: the filters this defeats judge a flow on its
	// opening datagram and then stop looking.
	if noise != nil {
		if err := noise.send(ctx, pktConn, udpAddr); err != nil {
			return "", err
		}
	}

	pref := new(atomic.Int32)
	conn, err := quicdial.Dial(ctx, quicConfig, attempts, pref,
		func(attempt *quic.Config) (*quic.Conn, error) {
			return qTransport.DialEarly(ctx, udpAddr, cfg, attempt)
		})
	if err != nil {
		return "", err
	}
	alpn := conn.ConnectionState().TLS.NegotiatedProtocol
	conn.CloseWithError(0, "")
	return alpn, nil
}
