package libv2ray

// HTTP/3 support for FetchWeb and ResolveDoH, over QUIC v2 with a v1 fallback.
//
// v2 first is deliberate: some networks drop QUIC v1 Initial packets outright,
// and the drop poisons the flow before QUIC's own version negotiation can run.
// v1 stays reachable for peers that never implemented v2. The ladder comes from
// xray-core's transport/internet/quicdial, so this shares the core's ordering
// and its per-destination stickiness rather than reimplementing either.

import (
	"context"
	gotls "crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/GFW-knocker/Xray-core/transport/internet/quicdial"
)

// h3RoundTripper builds an http3.Transport for one request.
//
// Everything is torn down by the returned cleanup: the UDP socket is ours, not
// net/http's, so nothing else will close it.
func (o *transportOptions) h3RoundTripper(u *url.URL, echList []byte, state *connState) (http.RoundTripper, func(), error) {
	// Our own socket, dialed the same way the TCP path dials: no xray dialer, so
	// it follows OS routing exactly like the rest of FetchWeb.
	pktConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, nil, fmt.Errorf("h3: cannot open udp socket: %w", err)
	}

	parrot := !o.DisableChromeParrot
	qTransport := &quic.Transport{Conn: pktConn}
	if parrot {
		// Chrome sends no source connection ID; matching that is part of the
		// parrot rather than an optimisation.
		qTransport.ConnectionIDGenerator = quic.ZeroLengthConnectionIDGenerator{}
	}

	quicConfig := &quic.Config{
		// A single version, only to satisfy http3.Transport's validation. The
		// version actually dialed is chosen per attempt by quicdial.Dial below.
		Versions:        quicdial.H3[0],
		MaxIdleTimeout:  o.timeout(),
		KeepAlivePeriod: 0,
		// The default of quic-go/http3, which differs from plain quic-go's.
		MaxIncomingStreams: -1,
		ChromeParrot:       parrot,
	}

	tlsConf := o.tlsConfig(u.Hostname(), echList, []string{"h3"})
	if o.ServerName == "" {
		// Leave SNI to http3, which derives it per authority. Pinning the
		// original host here would carry the wrong name onto a redirect that
		// crosses hosts.
		tlsConf.ServerName = ""
	}

	// Remembers which version last worked for this request, so the fallback is
	// paid once rather than on every dial a redirect chain makes.
	pref := new(atomic.Int32)

	rt := &http3.Transport{
		QUICConfig:      quicConfig,
		TLSClientConfig: tlsConf,
		Dial: func(ctx context.Context, addr string, cfg *gotls.Config, qcfg *quic.Config) (*quic.Conn, error) {
			if parrot {
				// ChromeParrot rejects a config carrying server-side fields.
				cfg.GetCertificate = nil
			}
			// addr is the authority http3 wants, which is not necessarily the
			// request's own host: a redirect across hosts dials a new one. Pin
			// the IP the same way rawDial does -- replace the host, keep the
			// port -- so h3 and the TCP paths agree on what "ip" means.
			target := addr
			if o.IP != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("cannot pin ip for %q: %w", addr, err)
				}
				target = net.JoinHostPort(o.IP, port)
			}
			udpAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				return nil, fmt.Errorf("h3: cannot resolve %q: %w", target, err)
			}
			conn, err := quicdial.Dial(ctx, qcfg, quicdial.H3, pref,
				func(attempt *quic.Config) (*quic.Conn, error) {
					return qTransport.DialEarly(ctx, udpAddr, cfg, attempt)
				})
			if err != nil {
				return nil, err
			}
			// quic-go's utls bridge drops ECHAccepted when it converts the
			// handshake state, so that field cannot be trusted here. It does not
			// need to be: the TLS stacks return ECHRejectionError when a server
			// refuses an offered config, so a handshake that completed with a
			// config list in hand is a handshake where ECH was accepted.
			if err := state.record("h3", len(echList) > 0); err != nil {
				conn.CloseWithError(0, "")
				return nil, err
			}
			return conn, nil
		},
	}

	cleanup := func() {
		rt.Close()
		qTransport.Close()
		pktConn.Close()
	}
	return rt, cleanup, nil
}

// quicVersionsDialed reports the ladder h3 will walk, for documentation and
// error messages.
func quicVersionsDialed() string {
	out := ""
	for i, attempt := range quicdial.H3 {
		if i > 0 {
			out += " then "
		}
		out += quicdial.Names(attempt)
	}
	return out
}
