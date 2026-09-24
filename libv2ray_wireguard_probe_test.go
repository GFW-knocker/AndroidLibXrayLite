package libv2ray

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/GFW-knocker/wireguard/conn"
	"github.com/GFW-knocker/wireguard/device"
	"github.com/GFW-knocker/wireguard/tun/tuntest"
	"golang.org/x/crypto/curve25519"
)

type wgKey struct {
	private device.NoisePrivateKey
	public  device.NoisePublicKey
}

func newKey(t *testing.T) wgKey {
	t.Helper()
	var k wgKey
	if _, err := io.ReadFull(rand.Reader, k.private[:]); err != nil {
		t.Fatal(err)
	}
	k.private[0] &= 248
	k.private[31] = (k.private[31] & 127) | 64
	pub, err := curve25519.X25519(k.private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(k.public[:], pub)
	return k
}

func (k wgKey) privB64() string { return base64.StdEncoding.EncodeToString(k.private[:]) }
func (k wgKey) pubB64() string  { return base64.StdEncoding.EncodeToString(k.public[:]) }

// newResponder starts a real wireguard-go device listening on loopback and
// returns its address. knownPeers are the initiator public keys it will accept;
// anything else it drops without answering.
func newResponder(t *testing.T, server wgKey, knownPeers ...device.NoisePublicKey) string {
	t.Helper()
	tun := tuntest.NewChannelTUN()
	dev := device.NewDevice(tun.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "responder: "))
	t.Cleanup(dev.Close)

	var cfg strings.Builder
	fmt.Fprintf(&cfg, "private_key=%s\n", hex.EncodeToString(server.private[:]))
	fmt.Fprintf(&cfg, "listen_port=0\n")
	for _, peer := range knownPeers {
		fmt.Fprintf(&cfg, "public_key=%s\n", hex.EncodeToString(peer[:]))
		fmt.Fprintf(&cfg, "allowed_ip=0.0.0.0/0\n")
	}
	if err := dev.IpcSet(cfg.String()); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	// The port was chosen by the OS; read it back out of the uapi.
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	port := ""
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port = strings.TrimPrefix(line, "listen_port=")
		}
	}
	if port == "" {
		t.Fatal("responder did not report a listen_port")
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func wgProbe(t *testing.T, opts map[string]any) *WireGuardResult {
	t.Helper()
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	return ProbeWireGuard(string(raw))
}

// The whole point: a real peer that knows us answers, and the answer
// authenticates.
func TestProbeWireGuardAlive(t *testing.T) {
	server, client := newKey(t), newKey(t)
	addr := newResponder(t, server, client.public)

	r := wgProbe(t, map[string]any{
		"address": addr, "publicKey": server.pubB64(),
		"privateKey": client.privB64(), "timeout": 4000,
	})
	t.Logf("alive=%v responded=%v type=%d size=%d attempts=%d rtt=%dms err=%q",
		r.Alive, r.Responded, r.ReplyType, r.ReplySize, r.Attempts, r.RttMs, r.RespError)
	if !r.Alive {
		t.Fatalf("Alive = false, want true (err %q)", r.RespError)
	}
	if !r.Responded || r.ReplyType != device.MessageResponseType || r.ReplySize != device.MessageResponseSize {
		t.Errorf("responded=%v type=%d size=%d, want a %d byte type-%d response",
			r.Responded, r.ReplyType, r.ReplySize, device.MessageResponseSize, device.MessageResponseType)
	}
	if r.RespError != "" {
		t.Errorf("RespError = %q, want empty", r.RespError)
	}
}

// The noise must not disturb the handshake: the responder drops the junk and
// answers the initiation that follows.
func TestProbeWireGuardWithNoise(t *testing.T) {
	server, client := newKey(t), newKey(t)
	addr := newResponder(t, server, client.public)

	for _, mode := range []string{"quic", "quicv1", "quicinit", "random", "d06b3343cf"} {
		// A responder drops an initiation arriving within HandshakeInitationRate
		// (20ms) of the last one it consumed, so space the cases out; otherwise
		// the first attempt of each is eaten by its flood protection.
		time.Sleep(60 * time.Millisecond)
		r := wgProbe(t, map[string]any{
			"address": addr, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 4000,
			"wnoise": mode, "wnoisecount": "3", "wnoisedelay": "0-2",
		})
		t.Logf("wnoise=%-10s alive=%v rtt=%dms err=%q", mode, r.Alive, r.RttMs, r.RespError)
		if !r.Alive {
			t.Errorf("wnoise=%s: Alive = false, want true (err %q)", mode, r.RespError)
		}
	}
}

// Everything that must NOT be reported as alive.
func TestProbeWireGuardRejects(t *testing.T) {
	server, client, stranger := newKey(t), newKey(t), newKey(t)
	addr := newResponder(t, server, client.public)

	// a port nothing listens on
	spare, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	dead := spare.LocalAddr().String()
	spare.Close()

	cases := []struct {
		name string
		opts map[string]any
	}{
		{"peer does not know us", map[string]any{
			"address": addr, "publicKey": server.pubB64(),
			"privateKey": stranger.privB64(), "timeout": 1500,
		}},
		{"wrong server key", map[string]any{
			"address": addr, "publicKey": stranger.pubB64(),
			"privateKey": client.privB64(), "timeout": 1500,
		}},
		{"reserved set, vanilla peer", map[string]any{
			"address": addr, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 1500, "reserved": "1,2,3",
		}},
		{"nothing listening", map[string]any{
			"address": dead, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 1500,
		}},
		{"wrong preshared key", map[string]any{
			"address": addr, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 1500,
			"presharedKey": stranger.pubB64(),
		}},
	}
	for _, c := range cases {
		r := wgProbe(t, c.opts)
		t.Logf("%-26s alive=%v responded=%v type=%d err=%q",
			c.name, r.Alive, r.Responded, r.ReplyType, r.RespError)
		if r.Alive {
			t.Errorf("%s: Alive = true, want false", c.name)
		}
		if r.RespError == "" {
			t.Errorf("%s: RespError is empty", c.name)
		}
	}
}

// Bad input is reported, not guessed at.
func TestProbeWireGuardBadOptions(t *testing.T) {
	good := newKey(t)
	cases := []struct {
		name string
		opts map[string]any
	}{
		{"no address", map[string]any{"publicKey": good.pubB64()}},
		{"bad address", map[string]any{"address": "nonsense", "publicKey": good.pubB64()}},
		{"no public key", map[string]any{"address": "127.0.0.1:1"}},
		{"short public key", map[string]any{"address": "127.0.0.1:1", "publicKey": base64.StdEncoding.EncodeToString([]byte("short"))}},
		{"not base64", map[string]any{"address": "127.0.0.1:1", "publicKey": "!!!!"}},
		{"bad reserved", map[string]any{"address": "127.0.0.1:1", "publicKey": good.pubB64(), "reserved": "1,2"}},
		{"reserved out of range", map[string]any{"address": "127.0.0.1:1", "publicKey": good.pubB64(), "reserved": "1,2,999"}},
		{"bad ip", map[string]any{"address": "127.0.0.1:1", "publicKey": good.pubB64(), "ip": "999.1.1.1"}},
		{"bad wnoise range", map[string]any{"address": "127.0.0.1:1", "publicKey": good.pubB64(), "wnoise": "quic", "wnoisecount": "9-2-3"}},
	}
	for _, c := range cases {
		r := wgProbe(t, c.opts)
		t.Logf("%-22s err=%q", c.name, r.RespError)
		if r.Alive || r.RespError == "" {
			t.Errorf("%s: alive=%v err=%q, want a reported failure", c.name, r.Alive, r.RespError)
		}
	}
	if r := ProbeWireGuard("{not json"); r.RespError == "" {
		t.Errorf("invalid json: RespError is empty")
	}
}

// The wire format: 148 bytes, type 1, and the client_id in the three bytes
// after it -- which is the only thing in the packet this code places itself.
func TestInitiationWireFormat(t *testing.T) {
	server, client := newKey(t), newKey(t)

	plain, packet, err := createInitiation(client.private, server.public, [3]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != device.MessageInitiationSize {
		t.Fatalf("len = %d, want %d", len(packet), device.MessageInitiationSize)
	}
	if packet[0] != device.MessageInitiationType {
		t.Errorf("type byte = %d, want %d", packet[0], device.MessageInitiationType)
	}
	if packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		t.Errorf("reserved = %v, want zeros", packet[1:4])
	}
	if plain.localIndex == 0 {
		t.Errorf("localIndex is zero")
	}

	_, withID, err := createInitiation(client.private, server.public, [3]byte{0xAA, 0xBB, 0xCC})
	if err != nil {
		t.Fatal(err)
	}
	if withID[0] != device.MessageInitiationType {
		t.Errorf("type byte = %d, want %d", withID[0], device.MessageInitiationType)
	}
	if withID[1] != 0xAA || withID[2] != 0xBB || withID[3] != 0xCC {
		t.Errorf("reserved = % x, want aa bb cc", withID[1:4])
	}
	// Two initiations must never be identical: a repeated one is a replay and
	// the peer drops it.
	if string(packet[4:]) == string(withID[4:]) {
		t.Errorf("two initiations came out identical")
	}
}

// Each attempt must be a fresh initiation, or a retry is a replay the peer
// ignores. Point the probe at a silent socket and count the datagrams.
func TestProbeWireGuardRetriesAreFresh(t *testing.T) {
	server := newKey(t)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	seen := make(chan []byte, 8)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := sink.ReadFromUDP(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			seen <- cp
		}
	}()

	r := wgProbe(t, map[string]any{
		"address": sink.LocalAddr().String(), "publicKey": server.pubB64(),
		"timeout": 1200, "attempts": 3,
	})
	if r.Alive {
		t.Fatalf("Alive = true against a silent socket")
	}
	if r.Attempts != 3 {
		t.Errorf("Attempts = %d, want 3", r.Attempts)
	}
	close(seen)
	var packets [][]byte
	for p := range seen {
		packets = append(packets, p)
	}
	t.Logf("attempts=%d datagrams=%d err=%q", r.Attempts, len(packets), r.RespError)
	if len(packets) != 3 {
		t.Fatalf("sent %d datagrams, want 3", len(packets))
	}
	for i := 1; i < len(packets); i++ {
		if string(packets[i]) == string(packets[0]) {
			t.Errorf("datagram %d is identical to the first: a replay", i)
		}
	}
}
