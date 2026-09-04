package libv2ray

// Fetch utilities built on top of xray-core's own TLS-fragmentation, ECH and
// uTLS implementations. GetDataFromWeb in libv2ray_main.go is deliberately left
// untouched; everything here is additive.
//
// Two entry points, both taking a JSON options string so the gomobile binding
// signature stays stable as options are added:
//
//	FetchWeb(optionsJSON)   -> *FetchResult   HTTP(S) GET/POST
//	ResolveDoH(optionsJSON) -> *DNSResult     DNS query over DoH
//
// Both accept the same transport options: proxy, fragment, ECH, uTLS
// fingerprint and browser header profile.

import (
	"bufio"
	"compress/gzip"
	"context"
	gotls "crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	xproxy "golang.org/x/net/proxy"

	xutils "github.com/GFW-knocker/Xray-core/common/utils"
	xconf "github.com/GFW-knocker/Xray-core/infra/conf"
	xfragment "github.com/GFW-knocker/Xray-core/transport/internet/finalmask/fragment"
	xtls "github.com/GFW-knocker/Xray-core/transport/internet/tls"
)

const (
	defaultTimeoutMs = 8000
	maxBodyBytes     = 32 << 20 // 32 MiB
	maxDNSBytes      = 64 << 10
)

// FetchResult is the result of FetchWeb.
type FetchResult struct {
	RespBody    string // response body, gzip-decoded
	RespHeader  string // X-From-Server, for parity with GetDataFromWeb
	RespHeaders string // all response headers, as a JSON object
	RespError   string // empty on success
	StatusCode  int
	Proto       string // "HTTP/1.1", "HTTP/2.0"
	EchAccepted bool   // true only if the server actually accepted ECH
}

// DNSResult is the result of ResolveDoH.
type DNSResult struct {
	Answers     string // JSON array of {name,type,ttl,value}
	IPs         string // comma-separated A/AAAA answers, convenience field
	Rcode       string // "NOERROR", "NXDOMAIN", ...
	TTL         int    // TTL of the first answer
	Proto       string
	EchAccepted bool
	RespError   string
}

// ---------------------------------------------------------------------------
// options
// ---------------------------------------------------------------------------

type echOptions struct {
	// Domain whose HTTPS (type 65) record carries the ECHConfigList. Defaults
	// to the request host when empty.
	Domain string `json:"domain"`
	// DoH endpoint used to look the record up, e.g. https://1.1.1.1/dns-query.
	DoH string `json:"doh"`
	// ConfigList is a base64 ECHConfigList, used verbatim when set. Skips DNS.
	ConfigList string `json:"configList"`
}

// transportOptions is shared by both entry points.
type transportOptions struct {
	// Proxy is an http:// or socks5:// URL. Empty means direct, which follows
	// OS routing exactly like GetDataFromWeb does.
	Proxy string `json:"proxy"`
	// IP pins the address to connect to, skipping DNS resolution of the URL's
	// host. The host is still used for SNI, certificate verification and the
	// Host header, so this is how you front a request through a chosen edge
	// address. The port keeps coming from the URL, so a non-standard one goes
	// in the URL itself (https://host:2053/path). Empty means normal
	// resolution. Applies through Proxy too: the CONNECT / SOCKS request then
	// names the pinned address.
	IP string `json:"ip"`
	// Timeout for the whole operation, in milliseconds.
	Timeout int `json:"timeout"`
	// AllowInsecure skips certificate verification.
	AllowInsecure bool `json:"allowInsecure"`
	// ServerName overrides the SNI / certificate name.
	ServerName string `json:"serverName"`
	// Fingerprint selects a uTLS ClientHello ("chrome", "firefox", ...).
	// Empty means standard library crypto/tls, which is the recommended
	// default: ECH works and HTTP/2 is negotiated automatically.
	Fingerprint string `json:"fingerprint"`
	// Fragment splits the TLS ClientHello. Same JSON shape as an xray config's
	// fragment mask. Cannot be combined with Proxy.
	Fragment *xconf.FragmentMask `json:"fragment"`
	// Ech enables Encrypted Client Hello.
	Ech *echOptions `json:"ech"`
	// Browser selects a header profile: chrome, edge, firefox, safari, curl,
	// golang. Defaults to chrome.
	Browser string `json:"browser"`
	// Variant selects the request context: nav, fetch, ws. Defaults to nav for
	// GET and fetch for everything else.
	Variant string `json:"variant"`
	// UserAgent overrides the profile's User-Agent while keeping its other
	// headers.
	UserAgent string `json:"userAgent"`
	// Headers are set last and win over everything above.
	Headers map[string]string `json:"headers"`
}

type fetchOptions struct {
	transportOptions
	URL    string `json:"url"`
	Method string `json:"method"`
	Data   string `json:"data"`
}

type dohOptions struct {
	transportOptions
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Server string `json:"server"`
}

func (o *transportOptions) timeout() time.Duration {
	if o.Timeout <= 0 {
		return defaultTimeoutMs * time.Millisecond
	}
	return time.Duration(o.Timeout) * time.Millisecond
}

func (o *transportOptions) echEnabled() bool {
	return o.Ech != nil && (o.Ech.DoH != "" || o.Ech.ConfigList != "")
}

func (o *transportOptions) validate() error {
	if o.IP != "" && net.ParseIP(o.IP) == nil {
		return fmt.Errorf("ip %q is not a valid IP address", o.IP)
	}
	if o.Fragment != nil && o.Proxy != "" {
		return fmt.Errorf("fragment cannot be combined with proxy: the proxy " +
			"reassembles the stream, so fragmentation would be a silent no-op; " +
			"configure fragmentation in the xray outbound instead")
	}
	if o.Fingerprint == "" {
		return nil
	}
	if xtls.GetFingerprint(o.Fingerprint) == nil {
		return fmt.Errorf("unknown fingerprint %q", o.Fingerprint)
	}
	if !o.echEnabled() {
		return nil
	}
	// Only modern Chrome/Firefox hellos can carry ECH; the others fail the
	// handshake with "malformed outer client hello" or a plain handshake
	// failure. "random" re-rolls per process start out of a pool that contains
	// incompatible entries, so it would fail nondeterministically.
	fp := strings.ToLower(o.Fingerprint)
	switch fp {
	case "chrome", "firefox":
		return nil
	case "random", "randomized", "randomizednoalpn":
		return fmt.Errorf("fingerprint %q cannot be used with ECH: it is chosen "+
			"randomly at startup and most hellos in the pool reject ECH; use "+
			"\"chrome\" or \"firefox\"", o.Fingerprint)
	}
	if strings.HasPrefix(fp, "hellochrome_") || strings.HasPrefix(fp, "hellofirefox_") {
		return nil
	}
	return fmt.Errorf("fingerprint %q does not support ECH; use \"chrome\" or \"firefox\"", o.Fingerprint)
}

// ---------------------------------------------------------------------------
// dialing
// ---------------------------------------------------------------------------

// rawDial opens a TCP connection to addr, through Proxy when set, and wraps it
// with the fragment writer when configured. No xray dialer is involved, so the
// connection follows OS routing (direct, for a package excluded from the VPN)
// exactly like GetDataFromWeb.
func (o *transportOptions) rawDial(ctx context.Context, addr string, frag *xfragment.Config) (net.Conn, error) {
	var conn net.Conn
	var err error

	// A pinned IP replaces only the address; the caller has already built the
	// TLS config and request from the URL's host, so SNI, certificate
	// verification and the Host header are untouched.
	if o.IP != "" {
		_, port, serr := net.SplitHostPort(addr)
		if serr != nil {
			return nil, fmt.Errorf("cannot pin ip for %q: %w", addr, serr)
		}
		addr = net.JoinHostPort(o.IP, port)
	}

	if o.Proxy == "" {
		d := &net.Dialer{Timeout: o.timeout(), KeepAlive: 15 * time.Second}
		conn, err = d.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = o.dialViaProxy(ctx, addr)
	}
	if err != nil {
		return nil, err
	}

	if frag == nil {
		return conn, nil
	}
	fc, ferr := xfragment.NewConnClient(frag, conn, false)
	if ferr != nil {
		conn.Close()
		return nil, ferr
	}
	return fc, nil
}

func (o *transportOptions) dialViaProxy(ctx context.Context, addr string) (net.Conn, error) {
	pu, err := url.Parse(o.Proxy)
	if err != nil {
		return nil, fmt.Errorf("bad proxy url: %w", err)
	}

	switch strings.ToLower(pu.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if pu.User != nil {
			pw, _ := pu.User.Password()
			auth = &xproxy.Auth{User: pu.User.Username(), Password: pw}
		}
		d, err := xproxy.SOCKS5("tcp", pu.Host, auth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return d.Dial("tcp", addr)

	case "http":
		d := &net.Dialer{Timeout: o.timeout()}
		conn, err := d.DialContext(ctx, "tcp", pu.Host)
		if err != nil {
			return nil, err
		}
		if err := proxyConnect(ctx, conn, pu, addr); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q (use http:// or socks5://)", pu.Scheme)
	}
}

// proxyConnect performs an HTTP CONNECT handshake for addr on conn.
func proxyConnect(ctx context.Context, conn net.Conn, pu *url.URL, addr string) error {
	var sb strings.Builder
	sb.WriteString("CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n")
	if pu.User != nil {
		pw, _ := pu.User.Password()
		cred := pu.User.Username() + ":" + pw
		sb.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(cred)) + "\r\n")
	}
	sb.WriteString("\r\n")

	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
		defer conn.SetDeadline(time.Time{})
	}
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
	}
	if br.Buffered() > 0 {
		return fmt.Errorf("proxy sent %d unexpected bytes after CONNECT", br.Buffered())
	}
	return nil
}

func (o *transportOptions) fragmentConfig() (*xfragment.Config, error) {
	if o.Fragment == nil {
		return nil, nil
	}
	// Build() applies xray's own validation. A hand-built Config with empty
	// length lists panics in the split loop, so never bypass this.
	msg, err := o.Fragment.Build()
	if err != nil {
		return nil, fmt.Errorf("invalid fragment: %w", err)
	}
	cfg, ok := msg.(*xfragment.Config)
	if !ok {
		return nil, fmt.Errorf("invalid fragment: unexpected config type %T", msg)
	}
	return cfg, nil
}

// ---------------------------------------------------------------------------
// ECH
// ---------------------------------------------------------------------------

type echCacheEntry struct {
	list   []byte
	expire time.Time
}

var echCache sync.Map // string -> echCacheEntry

// echConfigList resolves the ECHConfigList for the request. The lookup runs
// over this call's own transport, so it honours Proxy and Fragment. xray's
// tls.QueryRecord deliberately is not used: it dials via internet.DialSystem,
// which NewV2RayPoint points at the ProtectedDialer, so the DNS query would
// leave the device on a different path than the request itself.
func (o *transportOptions) echConfigList(ctx context.Context, host string) ([]byte, error) {
	if !o.echEnabled() {
		return nil, nil
	}
	if o.Ech.ConfigList != "" {
		list, err := base64.StdEncoding.DecodeString(o.Ech.ConfigList)
		if err != nil {
			return nil, fmt.Errorf("invalid ech.configList: %w", err)
		}
		return list, nil
	}

	domain := o.Ech.Domain
	if domain == "" {
		domain = host
	}
	key := domain + "|" + o.Ech.DoH + "|" + o.Proxy
	if v, ok := echCache.Load(key); ok {
		if e := v.(echCacheEntry); e.expire.After(time.Now()) {
			return e.list, nil
		}
	}

	// Look up without ECH, otherwise the lookup would itself need a lookup.
	// IP is dropped too: it pins the request's own host, and the ECH resolver
	// is a different server. Pin that one by putting a literal address in
	// ech.doh instead, e.g. https://1.1.1.1/dns-query.
	lookupOpts := *o
	lookupOpts.Ech = nil
	lookupOpts.IP = ""

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	reply, _, _, err := lookupOpts.dnsExchange(ctx, o.Ech.DoH, msg)
	if err != nil {
		return nil, fmt.Errorf("ECH lookup for %s failed: %w", domain, err)
	}

	list, ttl := extractECH(reply, domain)
	if len(list) == 0 {
		return nil, fmt.Errorf("no ECH record for %s: an HTTPS/type-65 record with an ech key is required", domain)
	}
	if ttl == 0 {
		ttl = 600
	}
	echCache.Store(key, echCacheEntry{list: list, expire: time.Now().Add(time.Duration(ttl) * time.Second)})
	return list, nil
}

func extractECH(reply *dns.Msg, domain string) ([]byte, uint32) {
	if reply == nil {
		return nil, 0
	}
	for _, ans := range reply.Answer {
		https, ok := ans.(*dns.HTTPS)
		if !ok || !strings.EqualFold(https.Hdr.Name, dns.Fqdn(domain)) {
			continue
		}
		for _, v := range https.Value {
			if ec, ok := v.(*dns.SVCBECHConfig); ok && len(ec.ECH) > 0 {
				return ec.ECH, ans.Header().Ttl
			}
		}
	}
	return nil, 0
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

func (o *transportOptions) tlsConfig(host string, echList []byte, alpn []string) *gotls.Config {
	sni := o.ServerName
	if sni == "" {
		sni = host
	}
	cfg := &gotls.Config{
		ServerName:         sni,
		InsecureSkipVerify: o.AllowInsecure,
		NextProtos:         alpn,
	}
	if len(echList) > 0 {
		cfg.EncryptedClientHelloConfigList = echList
	}
	return cfg
}

// connState records what the TLS layer negotiated. Needed only on the uTLS
// path; on the standard path net/http reports it via Response.TLS.
type connState struct {
	mu          sync.Mutex
	proto       string
	echAccepted bool
	set         bool
}

func (s *connState) record(proto string, ech bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set && s.proto != proto {
		return fmt.Errorf("connection negotiated %q but an earlier one negotiated %q: "+
			"a redirect crossed an HTTP version boundary", proto, s.proto)
	}
	s.proto, s.echAccepted, s.set = proto, ech, true
	return nil
}

func (s *connState) snapshot() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proto, s.echAccepted
}

// handoffDialer hands a pre-dialed connection to the first dial, then dials
// fresh for anything after it (redirects).
type handoffDialer struct {
	mu      sync.Mutex
	pending net.Conn
	dial    func(ctx context.Context, addr string) (net.Conn, error)
}

func (h *handoffDialer) get(ctx context.Context, addr string) (net.Conn, error) {
	h.mu.Lock()
	if c := h.pending; c != nil {
		h.pending = nil
		h.mu.Unlock()
		return c, nil
	}
	h.mu.Unlock()
	return h.dial(ctx, addr)
}

func (h *handoffDialer) discard() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c := h.pending; c != nil {
		h.pending = nil
		c.Close()
	}
}

// roundTripper builds the transport for one request.
//
// Standard path: net/http owns the TLS handshake, so HTTP/2 is negotiated
// automatically and Response.TLS carries the ECH result.
//
// uTLS path: the ClientHello dictates ALPN and net/http cannot read the state
// off a *utls.UConn, so the handshake happens here and the negotiated protocol
// selects between net/http and x/net/http2 explicitly.
func (o *transportOptions) roundTripper(ctx context.Context, u *url.URL, state *connState) (http.RoundTripper, func(), error) {
	noop := func() {}

	frag, err := o.fragmentConfig()
	if err != nil {
		return nil, nil, err
	}

	if u.Scheme == "http" {
		return &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return o.rawDial(ctx, addr, frag)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: o.timeout(),
		}, noop, nil
	}

	echList, err := o.echConfigList(ctx, u.Hostname())
	if err != nil {
		return nil, nil, err
	}

	if o.Fingerprint == "" {
		return &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return o.rawDial(ctx, addr, frag)
			},
			TLSClientConfig:       o.tlsConfig(u.Hostname(), echList, []string{"h2", "http/1.1"}),
			ForceAttemptHTTP2:     true,
			DisableKeepAlives:     true,
			TLSHandshakeTimeout:   o.timeout(),
			ResponseHeaderTimeout: o.timeout(),
		}, noop, nil
	}

	fp := xtls.GetFingerprint(o.Fingerprint)
	if fp == nil {
		return nil, nil, fmt.Errorf("unknown fingerprint %q", o.Fingerprint)
	}

	dialTLS := func(ctx context.Context, addr string) (net.Conn, error) {
		raw, err := o.rawDial(ctx, addr, frag)
		if err != nil {
			return nil, err
		}
		// NextProtos is left nil: a uTLS preset carries its own ALPN list and
		// overrides whatever the config asks for.
		uc, ok := xtls.UClient(raw, o.tlsConfig(u.Hostname(), echList, nil), fp).(*xtls.UConn)
		if !ok {
			raw.Close()
			return nil, fmt.Errorf("unexpected uTLS connection type")
		}
		if err := uc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		cs := uc.ConnectionState()
		if err := state.record(cs.NegotiatedProtocol, cs.ECHAccepted); err != nil {
			uc.Close()
			return nil, err
		}
		return uc, nil
	}

	// Probe once so ALPN is known before the protocol is chosen; that same
	// connection is then used for the request itself.
	probe, err := dialTLS(ctx, canonicalAddr(u))
	if err != nil {
		return nil, nil, err
	}
	handoff := &handoffDialer{pending: probe, dial: dialTLS}
	alpn, _ := state.snapshot()

	if alpn == "h2" {
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, _, addr string, _ *gotls.Config) (net.Conn, error) {
				return handoff.get(ctx, addr)
			},
		}, handoff.discard, nil
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return handoff.get(ctx, addr)
		},
		DisableKeepAlives:     true,
		ResponseHeaderTimeout: o.timeout(),
	}, handoff.discard, nil
}

func canonicalAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// applyHeaders installs a coherent browser header set, then the caller's
// overrides. Unlike xray's helper on its own, a custom UserAgent keeps the rest
// of the profile instead of suppressing it.
func (o *transportOptions) applyHeaders(h http.Header, variantDefault string) {
	browser := o.Browser
	if browser == "" {
		browser = "chrome"
	}
	variant := o.Variant
	if variant == "" {
		variant = variantDefault
	}
	// TryDefaultHeadersWith selects a profile from a sentinel in User-Agent.
	h.Set("User-Agent", browser)
	xutils.TryDefaultHeadersWith(h, variant)

	if o.UserAgent != "" {
		h.Set("User-Agent", o.UserAgent)
	}
	for k, v := range o.Headers {
		h.Set(k, v)
	}
}

// ---------------------------------------------------------------------------
// FetchWeb
// ---------------------------------------------------------------------------

// FetchWeb performs an HTTP(S) request with optional TLS fragmentation, ECH and
// uTLS fingerprinting.
//
//export FetchWeb *FetchResult
func FetchWeb(optionsJSON string) *FetchResult {
	opts := &fetchOptions{}
	if err := json.Unmarshal([]byte(optionsJSON), opts); err != nil {
		return &FetchResult{RespError: "invalid options json: " + err.Error()}
	}
	if opts.URL == "" {
		return &FetchResult{RespError: "url is required"}
	}
	if err := opts.validate(); err != nil {
		return &FetchResult{RespError: err.Error()}
	}

	u, err := url.Parse(opts.URL)
	if err != nil {
		return &FetchResult{RespError: "invalid url: " + err.Error()}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return &FetchResult{RespError: "unsupported url scheme " + u.Scheme}
	}

	method := strings.ToUpper(opts.Method)
	if method == "" {
		if opts.Data != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()

	state := &connState{}
	tr, cleanup, err := opts.roundTripper(ctx, u, state)
	if err != nil {
		return &FetchResult{RespError: err.Error()}
	}
	defer cleanup()

	var body io.Reader
	if opts.Data != "" {
		body = strings.NewReader(opts.Data)
	}
	req, err := http.NewRequestWithContext(ctx, method, opts.URL, body)
	if err != nil {
		return &FetchResult{RespError: err.Error()}
	}

	variantDefault := "nav"
	if method != "GET" {
		variantDefault = "fetch"
	}
	opts.applyHeaders(req.Header, variantDefault)
	if opts.Data != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := (&http.Client{Transport: tr, Timeout: opts.timeout()}).Do(req)
	if err != nil {
		return &FetchResult{RespError: err.Error()}
	}
	defer resp.Body.Close()

	payload, err := readBody(resp)
	if err != nil {
		return &FetchResult{RespError: err.Error()}
	}

	_, ech := state.snapshot()
	if resp.TLS != nil {
		ech = resp.TLS.ECHAccepted
	}

	out := &FetchResult{
		RespHeader:  resp.Header.Get("X-From-Server"),
		RespHeaders: marshalHeaders(resp.Header),
		StatusCode:  resp.StatusCode,
		Proto:       resp.Proto,
		EchAccepted: ech,
	}
	if resp.StatusCode > 299 {
		out.RespError = fmt.Sprintf("ERR status code: %d\n%s", resp.StatusCode, payload)
		return out
	}
	out.RespBody = payload
	return out
}

func readBody(resp *http.Response) (string, error) {
	var r io.Reader = io.LimitReader(resp.Body, maxBodyBytes)
	// net/http decompresses transparently only when it added Accept-Encoding
	// itself, which a caller-supplied header can prevent.
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return "", err
		}
		defer zr.Close()
		r = zr
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func marshalHeaders(h http.Header) string {
	b, err := json.Marshal(h)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// ResolveDoH
// ---------------------------------------------------------------------------

// ResolveDoH sends a DNS query over DoH, with the same optional fragmentation,
// ECH and fingerprinting as FetchWeb.
//
//export ResolveDoH *DNSResult
func ResolveDoH(optionsJSON string) *DNSResult {
	opts := &dohOptions{}
	if err := json.Unmarshal([]byte(optionsJSON), opts); err != nil {
		return &DNSResult{RespError: "invalid options json: " + err.Error()}
	}
	if opts.Domain == "" {
		return &DNSResult{RespError: "domain is required"}
	}
	if opts.Server == "" {
		return &DNSResult{RespError: "server is required (a DoH url, e.g. https://1.1.1.1/dns-query)"}
	}
	if err := opts.validate(); err != nil {
		return &DNSResult{RespError: err.Error()}
	}

	qtypeName := strings.ToUpper(opts.Type)
	if qtypeName == "" {
		qtypeName = "A"
	}
	qtype, ok := dns.StringToType[qtypeName]
	if !ok {
		return &DNSResult{RespError: "unknown record type " + qtypeName}
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout())
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(opts.Domain), qtype)

	reply, proto, ech, err := opts.transportOptions.dnsExchange(ctx, opts.Server, msg)
	if err != nil {
		return &DNSResult{RespError: err.Error(), Proto: proto, EchAccepted: ech}
	}

	answers, ips, ttl := summarizeAnswers(reply)
	return &DNSResult{
		Answers:     answers,
		IPs:         strings.Join(ips, ","),
		Rcode:       dns.RcodeToString[reply.Rcode],
		TTL:         ttl,
		Proto:       proto,
		EchAccepted: ech,
	}
}

type dnsAnswer struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	TTL   uint32 `json:"ttl"`
	Value string `json:"value"`
}

func summarizeAnswers(reply *dns.Msg) (string, []string, int) {
	out := make([]dnsAnswer, 0, len(reply.Answer))
	ips := make([]string, 0, len(reply.Answer))
	ttl := 0
	for i, ans := range reply.Answer {
		hdr := ans.Header()
		if i == 0 {
			ttl = int(hdr.Ttl)
		}
		out = append(out, dnsAnswer{
			Name:  strings.TrimSuffix(hdr.Name, "."),
			Type:  dns.TypeToString[hdr.Rrtype],
			TTL:   hdr.Ttl,
			Value: strings.TrimSpace(strings.TrimPrefix(ans.String(), hdr.String())),
		})
		switch rr := ans.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]", ips, ttl
	}
	return string(b), ips, ttl
}

// dnsExchange POSTs a wire-format DNS message to a DoH endpoint over this
// call's own transport. Returns the reply plus the HTTP protocol and whether
// ECH was accepted, so callers can see what actually happened on the wire.
func (o *transportOptions) dnsExchange(ctx context.Context, server string, msg *dns.Msg) (*dns.Msg, string, bool, error) {
	su, err := url.Parse(server)
	if err != nil {
		return nil, "", false, fmt.Errorf("invalid doh server %q: %w", server, err)
	}
	if su.Scheme != "https" && su.Scheme != "http" {
		return nil, "", false, fmt.Errorf("doh server must be http(s), got %q", su.Scheme)
	}

	// RFC 8484: the ID must be 0 so identical queries stay cacheable.
	msg.Id = 0
	msg.SetEdns0(4096, false)
	wire, err := msg.Pack()
	if err != nil {
		return nil, "", false, err
	}

	state := &connState{}
	tr, cleanup, err := o.roundTripper(ctx, su, state)
	if err != nil {
		return nil, "", false, err
	}
	defer cleanup()

	req, err := http.NewRequestWithContext(ctx, "POST", server, strings.NewReader(string(wire)))
	if err != nil {
		return nil, "", false, err
	}
	o.applyHeaders(req.Header, "fetch")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("X-Padding", xutils.H2Base62Pad(dohPadLen()))

	resp, err := (&http.Client{Transport: tr, Timeout: o.timeout()}).Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()

	_, ech := state.snapshot()
	if resp.TLS != nil {
		ech = resp.TLS.ECHAccepted
	}
	proto := resp.Proto

	if resp.StatusCode != http.StatusOK {
		return nil, proto, ech, fmt.Errorf("doh query failed with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSBytes))
	if err != nil {
		return nil, proto, ech, err
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, proto, ech, fmt.Errorf("malformed doh response: %w", err)
	}
	return reply, proto, ech, nil
}

// dohPadLen varies the padding width so query sizes are not constant. The
// exact value does not matter, only that it changes.
func dohPadLen() int {
	return 100 + int(time.Now().UnixNano()%700)
}
