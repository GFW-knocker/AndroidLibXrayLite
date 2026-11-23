package libv2ray

// End-to-end FetchWeb / ResolveDoH tests against local servers, covering the
// layers the core bump swapped underneath: x/net/http2 (a wrapper around
// net/http's HTTP/2 since Go 1.27), uTLS (new Chrome default), quic-go and its
// Chrome parrot, plus xray's fragment writer and ECH.

import (
	"crypto/ecdh"
	"crypto/rand"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/apernet/quic-go/http3"
	"github.com/miekg/dns"
	"golang.org/x/crypto/cryptobyte"
)

const testHost = "example.com"

// echoHandler reports what the server saw, so a test can check the protocol
// end to end rather than trusting the client.
func echoHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ech := r.TLS != nil && r.TLS.ECHAccepted
		// FetchResult.RespHeader reports this header.
		w.Header().Set("X-From-Server", "test-server")
		fmt.Fprintf(w, "proto=%s method=%s body=%s ech=%v ua=%q xh=%q auth=%q", r.Proto, r.Method, body, ech,
			r.UserAgent(), r.Header.Get("X-Test-Header"), r.Header.Get("Authorization"))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/", http.StatusFound)
	})
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(raw); err != nil || len(q.Question) != 1 {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.7")
		resp.Answer = append(resp.Answer, rr)
		out, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	})
	return mux
}

// echKeys makes an ECH key pair: the server-side key and the client-side
// base64 ECHConfigList for it.
func echKeys(t *testing.T, publicName string) (gotls.EncryptedClientHelloKey, string) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var c cryptobyte.Builder
	c.AddUint16(echConfigVersion)
	c.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7) // config_id
		b.AddUint16(echKemX25519)
		b.AddUint16LengthPrefixed(func(pk *cryptobyte.Builder) { pk.AddBytes(priv.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(cs *cryptobyte.Builder) {
			cs.AddUint16(echKdfSHA256)
			cs.AddUint16(echAeadAES128)
		})
		b.AddUint8(0)
		b.AddUint8LengthPrefixed(func(n *cryptobyte.Builder) { n.AddBytes([]byte(publicName)) })
		b.AddUint16(0) // extensions
	})
	cfg, err := c.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var l cryptobyte.Builder
	l.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cfg) })
	list, _ := l.Bytes()
	return gotls.EncryptedClientHelloKey{Config: cfg, PrivateKey: priv.Bytes(), SendAsRetry: true},
		base64.StdEncoding.EncodeToString(list)
}

type localServers struct {
	tlsURL  string // HTTPS, h2 + http/1.1, ECH-capable
	h3URL   string // HTTP/3 on UDP
	httpURL string
	echList string // base64 ECHConfigList the TLS server accepts
	tlsAddr string
}

func startLocalServers(t *testing.T) localServers {
	t.Helper()
	cert := gatewayCert(t, testHost, "Local Test", []string{testHost, "public.example"})
	key, list := echKeys(t, "public.example")

	tlsSrv := httptest.NewUnstartedServer(echoHandler())
	tlsSrv.EnableHTTP2 = true
	tlsSrv.TLS = &gotls.Config{
		Certificates:             []gotls.Certificate{cert},
		EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{key},
	}
	tlsSrv.StartTLS()
	t.Cleanup(tlsSrv.Close)

	plain := httptest.NewServer(echoHandler())
	t.Cleanup(plain.Close)

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{
		Handler: echoHandler(),
		TLSConfig: http3.ConfigureTLSConfig(&gotls.Config{
			Certificates:             []gotls.Certificate{cert},
			EncryptedClientHelloKeys: []gotls.EncryptedClientHelloKey{key},
		}),
	}
	go h3.Serve(pc)
	t.Cleanup(func() { h3.Close(); pc.Close() })

	return localServers{
		tlsURL:  tlsSrv.URL,
		h3URL:   "https://" + pc.LocalAddr().String(),
		httpURL: plain.URL,
		echList: list,
		tlsAddr: strings.TrimPrefix(tlsSrv.URL, "https://"),
	}
}

func fetch(t *testing.T, opts map[string]any) *FetchResult {
	t.Helper()
	if _, ok := opts["timeout"]; !ok {
		opts["timeout"] = 6000
	}
	raw, _ := json.Marshal(opts)
	return FetchWeb(string(raw))
}

func TestFetchWebLocal(t *testing.T) {
	s := startLocalServers(t)
	frag := map[string]any{"packets": "tlshello", "length": "20-40", "delay": "0-1"}

	type tc struct {
		name      string
		opts      map[string]any
		wantProto string
		wantEch   bool
		wantErr   string
	}
	cases := []tc{
		{name: "http", opts: map[string]any{"url": s.httpURL + "/"}, wantProto: "HTTP/1.1"},
		{name: "http-fragment", opts: map[string]any{"url": s.httpURL + "/", "fragment": frag}, wantProto: "HTTP/1.1"},
		{name: "post", opts: map[string]any{"url": s.tlsURL + "/", "data": `{"a":1}`}, wantProto: "HTTP/2.0"},
		{name: "redirect-h2", opts: map[string]any{"url": s.tlsURL + "/redirect", "alpn": "h2"}, wantProto: "HTTP/2.0"},
		{name: "redirect-utls", opts: map[string]any{"url": s.tlsURL + "/redirect", "fingerprint": "chrome"}, wantProto: "HTTP/2.0"},
		{name: "fp-h1-mismatch", opts: map[string]any{"url": s.tlsURL + "/", "fingerprint": "chrome", "alpn": "h1"}, wantErr: "negotiated"},
		{name: "ech-probe", opts: map[string]any{"url": s.tlsURL + "/", "ech": map[string]any{"probe": "probe://public.example@" + s.tlsAddr}}, wantProto: "HTTP/2.0", wantEch: true},
		// No wantProto on uTLS+ECH: the server negotiates http/1.1 there, the
		// same on Xray-core v1.26.10 and v1.26.11 (uTLS's inner hello), so it is
		// not asserted either way.
		{name: "ech-probe-utls", opts: map[string]any{"url": s.tlsURL + "/", "fingerprint": "chrome", "ech": map[string]any{"probe": "probe://public.example@" + s.tlsAddr}}, wantEch: true},
		{name: "doh-h2-via-url", opts: map[string]any{"url": s.tlsURL + "/", "alpn": "h2", "fragment": frag, "fingerprint": "firefox"}, wantProto: "HTTP/2.0"},
	}
	for _, alpn := range []string{"auto", "h1", "h2"} {
		want := map[string]string{"auto": "HTTP/2.0", "h1": "HTTP/1.1", "h2": "HTTP/2.0"}[alpn]
		cases = append(cases,
			tc{name: "std-" + alpn, opts: map[string]any{"url": s.tlsURL + "/", "alpn": alpn}, wantProto: want},
			tc{name: "std-" + alpn + "-fragment", opts: map[string]any{"url": s.tlsURL + "/", "alpn": alpn, "fragment": frag}, wantProto: want},
			tc{name: "std-" + alpn + "-ech", opts: map[string]any{"url": s.tlsURL + "/", "alpn": alpn, "ech": map[string]any{"configList": s.echList}}, wantProto: want, wantEch: true},
		)
	}
	for _, fp := range []string{"chrome", "firefox", "hellochrome_133", "hellochrome_155", "safari", "random", "randomized"} {
		cases = append(cases,
			tc{name: "utls-" + fp, opts: map[string]any{"url": s.tlsURL + "/", "fingerprint": fp}},
			tc{name: "utls-" + fp + "-fragment", opts: map[string]any{"url": s.tlsURL + "/", "fingerprint": fp, "fragment": frag}},
		)
	}
	for _, fp := range []string{"chrome", "firefox", "hellochrome_155"} {
		cases = append(cases, tc{name: "utls-" + fp + "-ech", opts: map[string]any{"url": s.tlsURL + "/", "fingerprint": fp, "ech": map[string]any{"configList": s.echList}}, wantEch: true})
	}
	for _, q := range []struct{ name, ver, noise string }{
		{"auto", "", ""}, {"v1", "v1", ""}, {"v2", "v2", ""},
		{"v1-noise-quic", "v1", "quic"}, {"auto-quicinit", "", "quicinit"}, {"v2-noise-hex", "v2", "c06b3343cf08"},
	} {
		for _, parrot := range []bool{true, false} {
			o := map[string]any{"url": s.h3URL + "/", "alpn": "h3", "disableChromeParrot": !parrot}
			if q.ver != "" {
				o["quicVersion"] = q.ver
			}
			if q.noise != "" {
				o["wnoise"] = q.noise
			}
			cases = append(cases, tc{name: fmt.Sprintf("h3-%s-parrot=%v", q.name, parrot), opts: o, wantProto: "HTTP/3.0"})
		}
	}
	for _, parrot := range []bool{true, false} {
		cases = append(cases, tc{name: fmt.Sprintf("h3-ech-parrot=%v", parrot),
			opts:      map[string]any{"url": s.h3URL + "/", "alpn": "h3", "disableChromeParrot": !parrot, "quicVersion": "v1", "ech": map[string]any{"configList": s.echList}},
			wantProto: "HTTP/3.0", wantEch: true})
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.opts["allowInsecure"] = true
			if _, ok := c.opts["serverName"]; !ok && !strings.HasPrefix(c.opts["url"].(string), "http://") {
				c.opts["serverName"] = testHost
			}
			r := fetch(t, c.opts)
			if c.wantErr != "" {
				if !strings.Contains(r.RespError, c.wantErr) {
					t.Fatalf("RespError = %q, want it to contain %q", r.RespError, c.wantErr)
				}
				return
			}
			if r.RespError != "" || r.StatusCode != 200 {
				t.Fatalf("status %d, err %q", r.StatusCode, r.RespError)
			}
			if c.wantProto != "" && r.Proto != c.wantProto {
				t.Errorf("Proto = %q, want %q", r.Proto, c.wantProto)
			}
			// The server's view must agree with the client's.
			if !strings.Contains(r.RespBody, "proto="+r.Proto) {
				t.Errorf("client says %q, server saw %q", r.Proto, r.RespBody)
			}
			if r.EchAccepted != c.wantEch {
				t.Errorf("EchAccepted = %v, want %v (server: %q)", r.EchAccepted, c.wantEch, r.RespBody)
			}
			if c.wantEch && !strings.Contains(r.RespBody, "ech=true") {
				t.Errorf("server did not see ECH: %q", r.RespBody)
			}
		})
	}
}

func TestResolveDoHLocal(t *testing.T) {
	s := startLocalServers(t)
	for _, c := range []struct {
		name   string
		server string
		extra  map[string]any
		proto  string
	}{
		{"h2", s.tlsURL + "/dns-query", nil, "HTTP/2.0"},
		{"h1", s.tlsURL + "/dns-query", map[string]any{"alpn": "h1"}, "HTTP/1.1"},
		{"utls", s.tlsURL + "/dns-query", map[string]any{"fingerprint": "chrome"}, "HTTP/2.0"},
		{"ech", s.tlsURL + "/dns-query", map[string]any{"ech": map[string]any{"configList": s.echList}}, "HTTP/2.0"},
		{"h3", s.h3URL + "/dns-query", map[string]any{"alpn": "h3", "quicVersion": "v1"}, "HTTP/3.0"},
		{"h3-noparrot", s.h3URL + "/dns-query", map[string]any{"alpn": "h3", "disableChromeParrot": true}, "HTTP/3.0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := map[string]any{"server": c.server, "domain": "test.example", "type": "A",
				"allowInsecure": true, "serverName": testHost, "timeout": 6000}
			for k, v := range c.extra {
				o[k] = v
			}
			raw, _ := json.Marshal(o)
			r := ResolveDoH(string(raw))
			if r.RespError != "" {
				t.Fatalf("ResolveDoH: %s", r.RespError)
			}
			if r.IPs != "192.0.2.7" || r.Rcode != "NOERROR" || r.Proto != c.proto {
				t.Fatalf("got IPs=%q rcode=%q proto=%q, want 192.0.2.7 NOERROR %s", r.IPs, r.Rcode, r.Proto, c.proto)
			}
		})
	}
}

// Malformed input must come back as RespError, never as a panic.
func TestFetchWebBadInputNoPanic(t *testing.T) {
	for _, in := range []string{
		``, `{`, `{}`, `{"url":"ftp://x"}`, `{"url":"http://exa mple.com"}`,
		`{"url":"https://x","alpn":"h9"}`, `{"url":"https://x","fingerprint":"nope"}`,
		`{"url":"https://x","fingerprint":"unsafe"}`, `{"url":"https://x","alpn":"h3","fingerprint":"chrome"}`,
		`{"url":"https://x","wnoise":"quic"}`, `{"url":"https://x","alpn":"h3","wnoise":"zz"}`,
		`{"url":"https://x","ech":{"configList":"!!!"}}`, `{"url":"https://x","ech":{"probe":"probe://"}}`,
		`{"url":"https://x","fragment":{"packets":"tlshello","length":"0"}}`, `{"url":"https://x","ip":"nope"}`,
	} {
		if r := FetchWeb(in); r == nil || r.RespError == "" {
			t.Errorf("FetchWeb(%s) gave no error: %+v", in, r)
		}
	}
	for _, in := range []string{``, `{}`, `{"domain":"x"}`, `{"domain":"x","server":"https://x","type":"BOGUS"}`, `{"domain":"x","server":"ftp://x"}`} {
		if r := ResolveDoH(in); r == nil || r.RespError == "" {
			t.Errorf("ResolveDoH(%s) gave no error: %+v", in, r)
		}
	}
}

// connectProxy is a minimal HTTP CONNECT proxy, standing in for a running
// xray's http inbound.
func connectProxy(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var tunnels atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		hj, _ := w.(http.Hijacker)
		w.WriteHeader(http.StatusOK)
		down, _, err := hj.Hijack()
		if err != nil {
			up.Close()
			return
		}
		tunnels.Add(1)
		go func() { io.Copy(up, down); up.Close() }()
		go func() { io.Copy(down, up); down.Close() }()
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &tunnels
}

// Option combinations the other tests leave out: a pinned "ip" with the real
// host in the URL, fragment "lengths"/"delays" lists with "maxSplit", an ECH
// probe written without a scheme, an http proxy, and a custom userAgent and
// headers on top of the "golang" browser profile.
func TestFetchWebOptionCombinations(t *testing.T) {
	s := startLocalServers(t)
	host, port, _ := net.SplitHostPort(s.tlsAddr)
	url := "https://" + net.JoinHostPort(testHost, port) + "/api"

	// A zero-length first record is a valid fragment setting, but Go's TLS
	// server rejects a zero-length handshake record, so it is checked
	// separately below and the full exchange runs with non-empty records.
	fragment := func(lengths ...string) map[string]any {
		return map[string]any{
			"url": url, "method": "POST", "data": `{"key":"x"}`, "ip": host, "alpn": "h2",
			"timeout": 8000, "allowInsecure": true,
			"fragment": map[string]any{"packets": "tlshello", "lengths": lengths,
				"delays": []string{"0"}, "maxSplit": "1000"},
			"browser": "golang", "userAgent": "test-agent/1.0",
			"headers": map[string]string{"Content-Type": "application/json; charset=UTF-8", "X-Test-Header": "test-value"},
		}
	}
	fragRoute := fragment("30-50")
	t.Run("fragment-empty-record-sent", func(t *testing.T) {
		raw, _ := json.Marshal(fragment("0", "30-50"))
		// The Go server answering unexpected_message proves the empty record
		// reached it ahead of the ClientHello.
		if r := FetchWeb(string(raw)); !strings.Contains(r.RespError, "unexpected message") {
			t.Fatalf("want the Go server to reject the empty record, got status %d err %q", r.StatusCode, r.RespError)
		}
	})
	// "public name @ address", no scheme.
	echRoute := map[string]any{
		"url": url, "method": "POST", "data": `{"key":"x"}`, "ip": host, "alpn": "h2",
		"timeout": 8000, "allowInsecure": true,
		"ech":     map[string]any{"probe": "public.example@" + s.tlsAddr},
		"browser": "golang", "userAgent": "test-agent/1.0",
		"headers": map[string]string{"X-Test-Header": "test-value", "Authorization": "Bearer test-token"},
	}
	proxyURL, tunnels := connectProxy(t)
	viaProxy := map[string]any{
		"url": url, "method": "POST", "data": `{"key":"x"}`, "ip": host, "timeout": 8000, "allowInsecure": true,
		"proxy": proxyURL, "browser": "golang", "userAgent": "test-agent/2.0",
		"headers": map[string]string{"X-Test-Header": "test-value"},
	}

	for name, o := range map[string]map[string]any{"fragment": fragRoute, "ech": echRoute, "proxy": viaProxy} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(o)
			r := FetchWeb(string(raw))
			if r.RespError != "" || r.StatusCode != 200 {
				t.Fatalf("status %d err %q", r.StatusCode, r.RespError)
			}
			if r.RespHeader != "test-server" {
				t.Errorf("RespHeader = %q, want test-server", r.RespHeader)
			}
			if !strings.Contains(r.RespBody, `method=POST body={"key":"x"}`) {
				t.Errorf("server saw %q", r.RespBody)
			}
			if !strings.Contains(r.RespBody, `xh="test-value"`) || !strings.Contains(r.RespBody, `ua="`+o["userAgent"].(string)+`"`) {
				t.Errorf("headers lost: %q", r.RespBody)
			}
			if name == "ech" && (!r.EchAccepted || !strings.Contains(r.RespBody, "ech=true") || !strings.Contains(r.RespBody, `auth="Bearer test-token"`)) {
				t.Errorf("ECH route: EchAccepted=%v, server saw %q", r.EchAccepted, r.RespBody)
			}
			if name != "proxy" && r.Proto != "HTTP/2.0" {
				t.Errorf("Proto = %q, want HTTP/2.0", r.Proto)
			}
		})
	}
	if tunnels.Load() == 0 {
		t.Error("the proxy route did not go through the proxy")
	}
}
