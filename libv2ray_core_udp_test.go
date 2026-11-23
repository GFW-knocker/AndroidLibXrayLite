package libv2ray

// Tests for the paths the Xray-core bump touched outside the fetch code:
//
//   - ProtectedDialer's UDP branch, which now returns common/net's
//     PacketConnWrapper (moved out of transport/internet in v1.26.11), and the
//     core consumers that hard-assert that type: freedom's UDP path and the
//     WireGuard outbound, run end to end with the dialer installed exactly the
//     way NewV2RayPoint installs it on Android.
//   - MeasureOutboundDelay's app selection, which the core's new App order
//     would otherwise have changed.
//
// Everything runs on loopback; Protect is faked, since there is no VpnService.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GFW-knocker/wireguard/conn"
	"github.com/GFW-knocker/wireguard/device"
	"github.com/GFW-knocker/wireguard/tun/tuntest"

	"github.com/GFW-knocker/Xray-core/app/dispatcher"
	"github.com/GFW-knocker/Xray-core/app/dns/fakedns"
	applog "github.com/GFW-knocker/Xray-core/app/log"
	"github.com/GFW-knocker/Xray-core/app/proxyman"
	"github.com/GFW-knocker/Xray-core/app/router"
	appstats "github.com/GFW-knocker/Xray-core/app/stats"
	v2net "github.com/GFW-knocker/Xray-core/common/net"
	"github.com/GFW-knocker/Xray-core/common/serial"
	v2core "github.com/GFW-knocker/Xray-core/core"
	v2serial "github.com/GFW-knocker/Xray-core/infra/conf/serial"
	v2internet "github.com/GFW-knocker/Xray-core/transport/internet"
)

// countingProtect is the VpnService stand-in: it allows every fd and counts
// them, which is how a test proves a socket came from ProtectedDialer.
type countingProtect struct{ n atomic.Int32 }

func (c *countingProtect) Protect(int) bool { c.n.Add(1); return true }

type refuseProtect struct{}

func (refuseProtect) Protect(int) bool { return false }

// udpEcho answers every datagram with "echo:" + payload, from its own address.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func readWithTimeout(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := c.Read(buf)
		ch <- result{buf[:n], err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read: %v", r.err)
		}
		return r.b
	case <-time.After(d):
		t.Fatalf("read timed out after %v", d)
	}
	return nil
}

// useProtectedDialer installs a ProtectedDialer as the core's system dialer,
// the way NewV2RayPoint does, and restores the default afterwards.
func useProtectedDialer(t *testing.T, p protectSet) {
	t.Helper()
	v2internet.UseAlternativeSystemDialer(NewPreotectedDialer(p))
	t.Cleanup(func() { v2internet.UseAlternativeSystemDialer(nil) })
}

func startCore(t *testing.T, config string) *v2core.Instance {
	t.Helper()
	cfg, err := v2serial.LoadJSONConfig(strings.NewReader(config))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	inst, err := v2core.New(cfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("core.Start: %v", err)
	}
	t.Cleanup(func() { inst.Close() })
	return inst
}

// ---------------------------------------------------------------------------
// ProtectedDialer, UDP, called directly
// ---------------------------------------------------------------------------

// Checks every property the core's consumers rely on, one by one:
// the concrete type, RemoteAddr's type, a real local port, Write/Read through
// Dest, ReadFrom handing back a *net.UDPAddr, and WriteTo another address on
// the same socket (WireGuard roaming).
func TestProtectedDialerUDPWrapper(t *testing.T) {
	echoA := udpEcho(t)
	echoB := udpEcho(t)

	p := &countingProtect{}
	d := NewPreotectedDialer(p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := d.Dial(ctx, nil, v2net.UDPDestination(v2net.ParseAddress("127.0.0.1"), v2net.Port(echoA.Port)), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	if p.n.Load() != 1 {
		t.Errorf("Protect called %d times, want 1", p.n.Load())
	}

	// proxy/wireguard/client.go and udphop assert this exact type and panic
	// on anything else.
	w, ok := c.(*v2net.PacketConnWrapper)
	if !ok {
		t.Fatalf("UDP dial returned %T, want *net.PacketConnWrapper", c)
	}
	// wireguard client.go:398 and udphop conn.go:116 assert this.
	ra, ok := c.RemoteAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("RemoteAddr is %T, want *net.UDPAddr", c.RemoteAddr())
	}
	if ra.Port != echoA.Port || !ra.IP.Equal(echoA.IP) {
		t.Errorf("RemoteAddr = %v, want %v", ra, echoA)
	}
	la, ok := w.PacketConn.LocalAddr().(*net.UDPAddr)
	if !ok || la.Port == 0 {
		t.Errorf("LocalAddr = %v, want a bound port", w.PacketConn.LocalAddr())
	}

	// Write goes to Dest.
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := readWithTimeout(t, c, 3*time.Second); string(got) != "echo:hello" {
		t.Fatalf("read %q, want echo:hello", got)
	}

	// WriteTo a different address on the same unconnected socket, and read the
	// source back the way freedom's PacketReader does: d.(*net.UDPAddr).
	if _, err := w.WriteTo([]byte("roam"), echoB); err != nil {
		t.Fatalf("WriteTo B: %v", err)
	}
	w.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, from, err := w.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	fromUDP, ok := from.(*net.UDPAddr)
	if !ok {
		t.Fatalf("ReadFrom addr is %T, want *net.UDPAddr", from)
	}
	if string(buf[:n]) != "echo:roam" || fromUDP.Port != echoB.Port || fromUDP.IP.To4() == nil || !fromUDP.IP.Equal(echoB.IP) {
		t.Fatalf("ReadFrom = %q from %v, want echo:roam from %v", buf[:n], from, echoB)
	}
	// xray's own IPAddress folds the v4-mapped form the dual-stack socket
	// reports back to IPv4, which freedom relies on to match the reply.
	if a := v2net.IPAddress(fromUDP.IP); a.Family() != v2net.AddressFamilyIPv4 {
		t.Errorf("v2net.IPAddress(%v) family = %v, want IPv4", fromUDP.IP, a.Family())
	}
}

// The prepared-server branch (Address == currentServer) builds the same
// wrapper from the cached resolution.
func TestProtectedDialerUDPPreparedServer(t *testing.T) {
	echo := udpEcho(t)
	p := &countingProtect{}
	d := NewPreotectedDialer(p)
	d.PrepareResolveChan()
	closeCh := make(chan struct{})
	defer close(closeCh)
	d.PrepareDomain(echo.String(), closeCh, false)
	close(d.ResolveChan())
	if !d.IsVServerReady() {
		t.Fatal("PrepareDomain did not resolve a loopback literal")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d.Dial(ctx, nil, v2net.UDPDestination(v2net.ParseAddress("127.0.0.1"), v2net.Port(echo.Port)), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	if _, ok := c.(*v2net.PacketConnWrapper); !ok {
		t.Fatalf("prepared UDP dial returned %T", c)
	}
	c.Write([]byte("prep"))
	if got := readWithTimeout(t, c, 3*time.Second); string(got) != "echo:prep" {
		t.Fatalf("read %q", got)
	}
	if !d.DestIpAddress().Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("DestIpAddress = %v", d.DestIpAddress())
	}
}

// A refused Protect must fail cleanly, not hand back a socket that would leak
// through the VPN.
func TestProtectedDialerUDPProtectRefused(t *testing.T) {
	echo := udpEcho(t)
	d := NewPreotectedDialer(refuseProtect{})
	c, err := d.Dial(context.Background(), nil, v2net.UDPDestination(v2net.ParseAddress("127.0.0.1"), v2net.Port(echo.Port)), nil)
	if err == nil {
		c.Close()
		t.Fatal("Dial succeeded although Protect refused the fd")
	}
}

// ---------------------------------------------------------------------------
// Through the core: freedom (UDP + TCP)
// ---------------------------------------------------------------------------

// freedom's UDP path switches on *net.PacketConnWrapper (freedom.go:535/610)
// and asserts ReadFrom's address. This drives it with our dialer installed.
func TestCoreFreedomUDPThroughProtectedDialer(t *testing.T) {
	echo := udpEcho(t)
	p := &countingProtect{}
	useProtectedDialer(t, p)
	inst := startCore(t, `{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"freedom","tag":"direct"}]}`)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := v2core.Dial(ctx, inst, v2net.UDPDestination(v2net.ParseAddress("127.0.0.1"), v2net.Port(echo.Port)))
	if err != nil {
		t.Fatalf("core.Dial: %v", err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("freedom-%d", i)
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := readWithTimeout(t, c, 5*time.Second); string(got) != "echo:"+msg {
			t.Fatalf("read %q, want echo:%s", got, msg)
		}
	}
	if p.n.Load() == 0 {
		t.Fatal("freedom did not dial through ProtectedDialer")
	}
}

func TestCoreFreedomTCPThroughProtectedDialer(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
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
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				c.Write(append([]byte("tcp:"), buf[:n]...))
			}()
		}
	}()
	p := &countingProtect{}
	useProtectedDialer(t, p)
	inst := startCore(t, `{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"freedom"}]}`)

	port := ln.Addr().(*net.TCPAddr).Port
	c, err := v2core.Dial(context.Background(), inst, v2net.TCPDestination(v2net.ParseAddress("127.0.0.1"), v2net.Port(port)))
	if err != nil {
		t.Fatalf("core.Dial: %v", err)
	}
	defer c.Close()
	c.Write([]byte("hi"))
	if got := readWithTimeout(t, c, 5*time.Second); string(got) != "tcp:hi" {
		t.Fatalf("read %q", got)
	}
	if p.n.Load() == 0 {
		t.Fatal("TCP did not dial through ProtectedDialer")
	}
}

// ---------------------------------------------------------------------------
// Through the core: WireGuard outbound (gvisor netstack) to a real peer
// ---------------------------------------------------------------------------

// wgPeer is a wireguard-go device on loopback whose TUN is a channel, so the
// test sees the decrypted inner packets and can inject replies.
func wgPeer(t *testing.T, server wgKey, client device.NoisePublicKey, clientIP string) (*tuntest.ChannelTUN, string) {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wgpeer: "))
	t.Cleanup(dev.Close)
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s/32\n",
		hex.EncodeToString(server.private[:]), hex.EncodeToString(client[:]), clientIP)
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(state, "\n") {
		if p, ok := strings.CutPrefix(line, "listen_port="); ok {
			return tun, net.JoinHostPort("127.0.0.1", p)
		}
	}
	t.Fatal("no listen_port")
	return nil, ""
}

func csum(b []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + sum>>16
	}
	return ^uint16(sum)
}

// udp4Packet builds an IPv4/UDP packet with valid checksums.
func udp4Packet(src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	src, dst = src.To4(), dst.To4()
	udpLen := 8 + len(payload)
	p := make([]byte, 20+udpLen)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], src)
	copy(p[16:20], dst)
	binary.BigEndian.PutUint16(p[10:], csum(p[:20], 0))

	u := p[20:]
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(udpLen))
	copy(u[8:], payload)
	var pseudo uint32
	for i := 0; i < 4; i += 2 {
		pseudo += uint32(binary.BigEndian.Uint16(src[i:])) + uint32(binary.BigEndian.Uint16(dst[i:]))
	}
	pseudo += 17 + uint32(udpLen)
	c := csum(u, pseudo)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return p
}

// The WireGuard outbound takes the socket from the system dialer and asserts
// *net.PacketConnWrapper (client.go:282/289). Here that socket comes from
// ProtectedDialer; a datagram goes out through the core's gvisor netstack,
// the peer decrypts it, and a reply comes back the same way.
func TestCoreWireGuardThroughProtectedDialer(t *testing.T) {
	for _, tc := range []struct{ name, noise string }{
		{"plain", ""},
		{"wnoise-quic", `,"wnoise":"quic","wnoisecount":"3","wnoisedelay":"1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newKey(t), newKey(t)
			const clientIP, peerIP = "10.77.0.2", "10.77.0.1"
			tun, endpoint := wgPeer(t, server, client.public, clientIP)

			p := &countingProtect{}
			useProtectedDialer(t, p)
			inst := startCore(t, fmt.Sprintf(`{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"wireguard","settings":{
				"secretKey":%q,"address":["%s/32"],"mtu":1420,"noKernelTun":true%s,
				"peers":[{"publicKey":%q,"endpoint":%q,"allowedIPs":["0.0.0.0/0"]}]}}]}`,
				client.privB64(), clientIP, tc.noise, server.pubB64(), endpoint))

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			c, err := v2core.Dial(ctx, inst, v2net.UDPDestination(v2net.ParseAddress(peerIP), 5353))
			if err != nil {
				t.Fatalf("core.Dial: %v", err)
			}
			defer c.Close()
			if _, err := c.Write([]byte("hello-wg")); err != nil {
				t.Fatalf("Write: %v", err)
			}

			// The peer decrypted it: the inner packet shows up on its TUN.
			var inner []byte
			select {
			case inner = <-tun.Inbound:
			case <-time.After(10 * time.Second):
				t.Fatalf("no packet reached the WireGuard peer (Protect calls: %d)", p.n.Load())
			}
			if len(inner) < 28 || inner[0]>>4 != 4 || inner[9] != 17 {
				t.Fatalf("peer got a non-UDPv4 packet: %x", inner)
			}
			if !net.IP(inner[12:16]).Equal(net.ParseIP(clientIP)) || !net.IP(inner[16:20]).Equal(net.ParseIP(peerIP)) {
				t.Fatalf("inner packet %v -> %v", net.IP(inner[12:16]), net.IP(inner[16:20]))
			}
			ihl := int(inner[0]&0x0f) * 4
			if !bytes.Equal(inner[ihl+8:], []byte("hello-wg")) {
				t.Fatalf("inner payload %q", inner[ihl+8:])
			}
			if p.n.Load() == 0 {
				t.Fatal("WireGuard did not dial through ProtectedDialer")
			}

			// Reply from the peer side, back through the tunnel.
			sport := binary.BigEndian.Uint16(inner[ihl:])
			reply := udp4Packet(net.ParseIP(peerIP), net.ParseIP(clientIP), 5353, sport, []byte("reply-wg"))
			select {
			case tun.Outbound <- reply:
			case <-time.After(5 * time.Second):
				t.Fatal("peer TUN did not take the reply")
			}
			if got := readWithTimeout(t, c, 10*time.Second); string(got) != "reply-wg" {
				t.Fatalf("read %q, want reply-wg", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// MeasureOutboundDelay
// ---------------------------------------------------------------------------

func appTypes(apps []*serial.TypedMessage) []string {
	out := make([]string, len(apps))
	for i, a := range apps {
		out[i] = a.Type
	}
	return out
}

// The selection must match what App[:5] picked on cores before v1.26.11, for
// every shape of config MahsaNG generates (stats/policy only with the speed
// display on, fakedns optional).
func TestMeasureAppsMatchesPreBumpSelection(t *testing.T) {
	var (
		tLog      = serial.GetMessageType(&applog.Config{})
		tDispatch = serial.GetMessageType(&dispatcher.Config{})
		tIn       = serial.GetMessageType(&proxyman.InboundConfig{})
		tOut      = serial.GetMessageType(&proxyman.OutboundConfig{})
		tRouter   = serial.GetMessageType(&router.Config{})
		tStats    = serial.GetMessageType(&appstats.Config{})
		tFake     = serial.GetMessageType(&fakedns.FakeDnsPoolMulti{})
	)
	const (
		ob      = `"outbounds":[{"protocol":"freedom","tag":"direct"}]`
		routing = `"routing":{"domainStrategy":"AsIs","rules":[{"type":"field","ip":["10.0.0.0/8"],"outboundTag":"direct"}]}`
		dns     = `"dns":{"servers":["localhost"]}`
		stats   = `"stats":{},"policy":{"system":{"statsOutboundUplink":true}}`
		fake    = `"fakedns":[{"ipPool":"198.18.0.0/15","poolSize":1000}]`
	)
	for _, tc := range []struct {
		name string
		cfg  string
		want []string
	}{
		{"typical", "{" + ob + "," + routing + "," + dns + "}", []string{tLog, tDispatch, tIn, tOut, tRouter}},
		{"speed-on", "{" + stats + "," + ob + "," + routing + "," + dns + "}", []string{tLog, tDispatch, tIn, tOut, tStats}},
		{"fakedns", "{" + fake + "," + ob + "," + routing + "," + dns + "}", []string{tFake, tLog, tDispatch, tIn, tOut}},
		{"minimal", "{" + ob + "}", []string{tLog, tDispatch, tIn, tOut}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := v2serial.LoadJSONConfig(strings.NewReader(tc.cfg))
			if err != nil {
				t.Fatal(err)
			}
			got := appTypes(measureApps(cfg.App))
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("kept apps\n got  %v\n want %v\n (core built %v)", got, tc.want, appTypes(cfg.App))
			}
		})
	}
}

func TestMeasureOutboundDelayLocal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	const ob = `"outbounds":[{"protocol":"freedom","tag":"direct"}]`
	for name, cfg := range map[string]string{
		"typical":  `{"log":{"loglevel":"warning"},` + ob + `,"routing":{"rules":[{"type":"field","ip":["10.0.0.0/8"],"outboundTag":"direct"}]},"dns":{"servers":["localhost"]}}`,
		"speed-on": `{"stats":{},"policy":{"system":{"statsOutboundUplink":true}},` + ob + `,"dns":{"servers":["localhost"]}}`,
		"fakedns":  `{"fakedns":[{"ipPool":"198.18.0.0/15","poolSize":1000}],` + ob + `}`,
		"minimal":  `{` + ob + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			delay, err := MeasureOutboundDelay(cfg, srv.URL+"/generate_204")
			if err != nil || delay < 0 {
				t.Fatalf("MeasureOutboundDelay = %d, %v", delay, err)
			}
		})
	}
}

// These used to dereference a nil *http.Request, which kills the app process
// under gomobile.
func TestBadURLsDoNotPanic(t *testing.T) {
	const bad = "http://exa mple.com/"
	if d, err := MeasureOutboundDelay(`{"outbounds":[{"protocol":"freedom"}]}`, bad); err == nil {
		t.Errorf("MeasureOutboundDelay(bad url) = %d, nil", d)
	}
	if r := GetDataFromWeb(bad, "", "", 2000, false, false, false); r.RespError == "" {
		t.Errorf("GetDataFromWeb(bad url) returned no error")
	}
	if r := GetDataFromWeb(bad, "{}", "", 2000, false, true, false); r.RespError == "" {
		t.Errorf("GetDataFromWeb(bad url, POST) returned no error")
	}
}
