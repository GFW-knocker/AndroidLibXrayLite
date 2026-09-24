package libv2ray

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/apernet/quic-go"
)

// gatewayCert mimics what a Cloudflare MASQUE edge presents: the subject CN and
// the issuer O are the two marks the scanner recognises.
func gatewayCert(t *testing.T, cn, issuerOrg string, sans []string) gotls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{issuerOrg}},
		Issuer:       pkix.Name{CommonName: cn, Organization: []string{issuerOrg}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     sans,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func serverTLS(t *testing.T, alpn []string, wantClientCert bool) *gotls.Config {
	return serverTLSVer(t, alpn, wantClientCert, 0)
}

func serverTLSVer(t *testing.T, alpn []string, wantClientCert bool, maxVer uint16) *gotls.Config {
	cfg := &gotls.Config{
		Certificates: []gotls.Certificate{
			gatewayCert(t, "masque.cloudflareclient.com", "Cloudflare, Inc.",
				[]string{"masque.cloudflareclient.com"}),
		},
		NextProtos: alpn,
		MaxVersion: maxVer,
	}
	if wantClientCert {
		// What a real gateway does: asks for a certificate and drops the
		// connection when none arrives, having already sent its own.
		cfg.ClientAuth = gotls.RequireAnyClientCert
	}
	return cfg
}

func startQUIC(t *testing.T, wantClientCert bool) string {
	t.Helper()
	ln, err := quic.ListenAddr("127.0.0.1:0", serverTLS(t, []string{"h3"}, wantClientCert), &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept(t.Context())
			if err != nil {
				return
			}
			go func() { <-conn.Context().Done() }()
		}
	}()
	return ln.Addr().String()
}

func startTCP(t *testing.T, alpn []string, wantClientCert bool) string {
	t.Helper()
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", serverTLS(t, alpn, wantClientCert))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := conn.(*gotls.Conn)
				_ = tc.Handshake()
				tc.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func probe(t *testing.T, opts map[string]any) *CertResult {
	t.Helper()
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	return ProbeCert(string(raw))
}

func checkGateway(t *testing.T, r *CertResult, wantProto string) {
	t.Helper()
	if r.CommonName != "masque.cloudflareclient.com" {
		t.Errorf("CommonName = %q, want masque.cloudflareclient.com (err=%q)", r.CommonName, r.RespError)
	}
	if r.IssuerOrg != "Cloudflare, Inc." {
		t.Errorf("IssuerOrg = %q, want %q", r.IssuerOrg, "Cloudflare, Inc.")
	}
	if r.DNSNames != "masque.cloudflareclient.com" {
		t.Errorf("DNSNames = %q", r.DNSNames)
	}
	if len(r.SpkiSha256) != 64 {
		t.Errorf("SpkiSha256 = %q, want 64 hex chars", r.SpkiSha256)
	}
	if r.Proto != wantProto {
		t.Errorf("Proto = %q, want %q", r.Proto, wantProto)
	}
	if r.ChainLen != 1 || len(r.Leaf) == 0 {
		t.Errorf("ChainLen = %d, len(Leaf) = %d", r.ChainLen, len(r.Leaf))
	}
	if r.NotAfter == "" {
		t.Errorf("NotAfter is empty")
	}
}

// The ordinary case: a gateway that completes the handshake.
func TestProbeCertH3(t *testing.T) {
	addr := startQUIC(t, false)
	for _, parrot := range []bool{true, false} {
		r := probe(t, map[string]any{
			"address": addr, "serverName": "consumer-masque.cloudflareclient.com",
			"alpn": "h3", "timeout": 8000, "quicVersion": "v1",
			"disableChromeParrot": !parrot,
		})
		t.Logf("parrot=%v -> cn=%q issuer=%q alpn=%q ok=%v rtt=%dms err=%q",
			parrot, r.CommonName, r.IssuerOrg, r.Alpn, r.HandshakeOK, r.RttMs, r.RespError)
		checkGateway(t, r, "h3")
		if !r.HandshakeOK {
			t.Errorf("parrot=%v: HandshakeOK = false, err = %q", parrot, r.RespError)
		}
		if r.Alpn != "h3" || !r.AlpnKnown {
			t.Errorf("parrot=%v: Alpn = %q known=%v, want h3", parrot, r.Alpn, r.AlpnKnown)
		}
	}
}

// The case that matters: it hangs up for want of a client certificate, and the
// certificate must survive that.
func TestProbeCertH3HangsUp(t *testing.T) {
	addr := startQUIC(t, true)
	r := probe(t, map[string]any{
		"address": addr, "serverName": "consumer-masque.cloudflareclient.com",
		"alpn": "h3", "timeout": 8000, "quicVersion": "v1",
	})
	// TLS 1.3 finishes on this side before the server's rejection arrives, so
	// HandshakeOK stays true here; what matters is that the certificate is in
	// hand either way.
	t.Logf("cn=%q ok=%v err=%q", r.CommonName, r.HandshakeOK, r.RespError)
	checkGateway(t, r, "h3")
}

// The noise priming must not disturb the handshake.
func TestProbeCertH3WithNoise(t *testing.T) {
	addr := startQUIC(t, false)
	for _, mode := range []string{"quicinit", "quic", "quicv1", "random"} {
		r := probe(t, map[string]any{
			"address": addr, "serverName": "consumer-masque.cloudflareclient.com",
			"alpn": "h3", "timeout": 8000, "quicVersion": "v1",
			"wnoise": mode, "wnoisecount": "2", "wnoisedelay": "0-2",
		})
		t.Logf("wnoise=%-9s -> cn=%q ok=%v err=%q", mode, r.CommonName, r.HandshakeOK, r.RespError)
		checkGateway(t, r, "h3")
		if !r.HandshakeOK {
			t.Errorf("wnoise=%s: HandshakeOK = false, err = %q", mode, r.RespError)
		}
	}
}

// TCP, where the alpn the peer echoes is itself the signal.
func TestProbeCertTCPAlpn(t *testing.T) {
	cases := []struct {
		name     string
		srvAlpn  []string
		wantAlpn string
	}{
		{"echoes h2", []string{"h2"}, "h2"},
		{"echoes none", nil, ""},
	}
	for _, c := range cases {
		addr := startTCP(t, c.srvAlpn, false)
		r := probe(t, map[string]any{
			"address": addr, "serverName": "consumer-masque.cloudflareclient.com",
			"alpn": "h2", "timeout": 8000,
		})
		t.Logf("%-12s -> alpn=%q known=%v ok=%v", c.name, r.Alpn, r.AlpnKnown, r.HandshakeOK)
		checkGateway(t, r, "tcp")
		if !r.HandshakeOK || !r.AlpnKnown || r.Alpn != c.wantAlpn {
			t.Errorf("%s: alpn = %q known = %v ok = %v, want alpn %q",
				c.name, r.Alpn, r.AlpnKnown, r.HandshakeOK, c.wantAlpn)
		}
	}
}

func TestProbeCertTCPHangsUp(t *testing.T) {
	addr := startTCP(t, []string{"h2"}, true)
	r := probe(t, map[string]any{
		"address": addr, "serverName": "consumer-masque.cloudflareclient.com",
		"alpn": "h2", "timeout": 8000,
	})
	t.Logf("tls1.3 cn=%q ok=%v err=%q", r.CommonName, r.HandshakeOK, r.RespError)
	checkGateway(t, r, "tcp")

	// Under TLS 1.2 the client authentication happens inside the handshake, so
	// the refusal lands before it completes. This is the path that proves the
	// certificate is captured from a handshake that FAILS.
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", serverTLSVer(t, []string{"h2"}, true, gotls.VersionTLS12))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*gotls.Conn).Handshake(); c.Close() }()
		}
	}()
	r = probe(t, map[string]any{
		"address": ln.Addr().String(), "serverName": "consumer-masque.cloudflareclient.com",
		"alpn": "h2", "timeout": 8000,
	})
	t.Logf("tls1.2 cn=%q ok=%v err=%q", r.CommonName, r.HandshakeOK, r.RespError)
	checkGateway(t, r, "tcp")
	if r.HandshakeOK {
		t.Errorf("tls1.2: HandshakeOK = true, want false")
	}
	if r.RespError == "" {
		t.Errorf("tls1.2: RespError is empty, want the handshake failure")
	}
	if r.AlpnKnown {
		t.Errorf("tls1.2: AlpnKnown = true, but the handshake never finished")
	}
}

// A closed port and a bad request must report, not panic.
func TestProbeCertFailures(t *testing.T) {
	// a port nothing listens on
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().String()
	l.Close()

	cases := []struct {
		name string
		opts map[string]any
	}{
		{"tcp dead", map[string]any{"address": dead, "alpn": "h2", "timeout": 1500}},
		{"h3 dead", map[string]any{"address": dead, "alpn": "h3", "timeout": 1500, "quicVersion": "v1"}},
		{"no address", map[string]any{"alpn": "h2"}},
		{"bad address", map[string]any{"address": "nonsense", "alpn": "h2"}},
		{"bad alpn", map[string]any{"address": dead, "alpn": "h9"}},
		{"wnoise on tcp", map[string]any{"address": dead, "alpn": "h2", "wnoise": "quicinit"}},
	}
	for _, c := range cases {
		r := probe(t, c.opts)
		t.Logf("%-14s -> err=%q cn=%q", c.name, r.RespError, r.CommonName)
		if r.RespError == "" {
			t.Errorf("%s: RespError is empty, want a failure", c.name)
		}
		if r.CommonName != "" {
			t.Errorf("%s: CommonName = %q, want empty", c.name, r.CommonName)
		}
	}
	if r := ProbeCert("{not json"); r.RespError == "" {
		t.Errorf("invalid json: RespError is empty")
	}
}

// An edge that is not a gateway must come back with its own name, so the
// caller can reject it rather than being told nothing.
func TestProbeCertOtherEdge(t *testing.T) {
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{
			gatewayCert(t, "cloudflareclient.com", "Let's Encrypt", []string{"*.cloudflareclient.com"}),
		},
		NextProtos: []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*gotls.Conn).Handshake(); c.Close() }()
		}
	}()

	r := probe(t, map[string]any{
		"address": ln.Addr().String(), "serverName": "consumer-masque.cloudflareclient.com",
		"alpn": "h2", "timeout": 8000,
	})
	t.Logf("cn=%q issuer=%q sans=%q", r.CommonName, r.IssuerOrg, r.DNSNames)
	if r.CommonName != "cloudflareclient.com" || r.IssuerOrg != "Let's Encrypt" {
		t.Errorf("cn = %q issuer = %q, want the web edge's own", r.CommonName, r.IssuerOrg)
	}
	if r.DNSNames != "*.cloudflareclient.com" {
		t.Errorf("DNSNames = %q", r.DNSNames)
	}
}
