package libv2ray

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// settle waits for goroutines started by a probe to finish, then reports how
// many are running. Nothing here should need the wait -- it exists so a slow
// teardown is reported as a number rather than as a flake.
func settle(t *testing.T, want int) int {
	t.Helper()
	var n int
	for i := 0; i < 100; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n = runtime.NumGoroutine()
		if n <= want {
			return n
		}
	}
	return n
}

func goroutineDump() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

// Every probe must leave the process exactly as it found it: no reader
// goroutine, no keepalive timer, no socket.
func TestProbesDoNotLeakGoroutines(t *testing.T) {
	server, client := newKey(t), newKey(t)
	wgAddr := newResponder(t, server, client.public)
	quicAddr := startQUIC(t, false)
	tcpAddr := startTCP(t, []string{"h2"}, false)

	spare, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	dead := spare.LocalAddr().String()
	spare.Close()

	run := func() {
		raw, _ := json.Marshal(map[string]any{
			"address": wgAddr, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 2000, "attempts": 1,
			"wnoise": "quic", "wnoisecount": "2", "wnoisedelay": "0-1",
		})
		ProbeWireGuard(string(raw))

		raw, _ = json.Marshal(map[string]any{
			"address": quicAddr, "serverName": "consumer-masque.cloudflareclient.com",
			"alpn": "h3", "timeout": 2000, "quicVersion": "v1",
			"wnoise": "quicinit", "wnoisecount": "1", "wnoisedelay": "0-1",
		})
		ProbeCert(string(raw))

		raw, _ = json.Marshal(map[string]any{
			"address": tcpAddr, "serverName": "consumer-masque.cloudflareclient.com",
			"alpn": "h2", "timeout": 2000,
		})
		ProbeCert(string(raw))

		// the failure paths matter most: they are where a socket gets forgotten
		raw, _ = json.Marshal(map[string]any{
			"address": dead, "publicKey": server.pubB64(),
			"privateKey": client.privB64(), "timeout": 300, "attempts": 1,
		})
		ProbeWireGuard(string(raw))

		raw, _ = json.Marshal(map[string]any{
			"address": dead, "serverName": "x", "alpn": "h3",
			"timeout": 300, "quicVersion": "v1",
		})
		ProbeCert(string(raw))
	}

	// warm up once so lazily-started machinery is not counted as a leak
	run()
	base := settle(t, 0)
	t.Logf("baseline goroutines after warm-up: %d", base)

	const rounds = 20
	for i := 0; i < rounds; i++ {
		run()
	}
	after := settle(t, base)
	t.Logf("after %d rounds of 5 probes: %d goroutines (baseline %d)", rounds, after, base)
	if after > base {
		t.Errorf("goroutines grew from %d to %d after %d rounds:\n%s",
			base, after, rounds, goroutineDump())
	}
}

// The scanner will run these wide. Nothing may be shared between calls.
func TestProbesAreSafeInParallel(t *testing.T) {
	server, client := newKey(t), newKey(t)
	wgAddr := newResponder(t, server, client.public)
	quicAddr := startQUIC(t, false)
	tcpAddr := startTCP(t, []string{"h2"}, false)

	base := settle(t, 0)

	const workers = 24
	var wg sync.WaitGroup
	errs := make(chan string, workers*3)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// A WireGuard responder drops an initiation arriving within 20ms of
			// the last one it consumed, so a parallel burst legitimately loses
			// some. Only assert the ones that did get through authenticated.
			raw, _ := json.Marshal(map[string]any{
				"address": wgAddr, "publicKey": server.pubB64(),
				"privateKey": client.privB64(), "timeout": 6000, "attempts": 4,
			})
			r := ProbeWireGuard(string(raw))
			if r.Responded && !r.Alive {
				errs <- fmt.Sprintf("worker %d: wireguard responded but did not authenticate: %q", i, r.RespError)
			}

			raw, _ = json.Marshal(map[string]any{
				"address": quicAddr, "serverName": "consumer-masque.cloudflareclient.com",
				"alpn": "h3", "timeout": 6000, "quicVersion": "v1",
			})
			c := ProbeCert(string(raw))
			if c.CommonName != "masque.cloudflareclient.com" {
				errs <- fmt.Sprintf("worker %d: h3 cn = %q err %q", i, c.CommonName, c.RespError)
			}

			raw, _ = json.Marshal(map[string]any{
				"address": tcpAddr, "serverName": "consumer-masque.cloudflareclient.com",
				"alpn": "h2", "timeout": 6000,
			})
			c = ProbeCert(string(raw))
			if c.CommonName != "masque.cloudflareclient.com" || c.Alpn != "h2" {
				errs <- fmt.Sprintf("worker %d: tcp cn = %q alpn = %q err %q", i, c.CommonName, c.Alpn, c.RespError)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	var failures []string
	for e := range errs {
		failures = append(failures, e)
	}
	if len(failures) > 0 {
		t.Errorf("%d failures in %d parallel workers:\n%s", len(failures), workers, strings.Join(failures, "\n"))
	}

	after := settle(t, base)
	t.Logf("%d workers x 3 probes in parallel: %d goroutines (baseline %d)", workers, after, base)
	if after > base {
		t.Errorf("goroutines grew from %d to %d", base, after)
	}
}

// Nothing in either probe may construct a WireGuard Device, a TUN or a netstack:
// they would bring threads, a routing table and a keepalive timer with them.
func TestProbesTouchNoDevice(t *testing.T) {
	server, client := newKey(t), newKey(t)
	addr := newResponder(t, server, client.public)

	before := goroutineDump()
	raw, _ := json.Marshal(map[string]any{
		"address": addr, "publicKey": server.pubB64(),
		"privateKey": client.privB64(), "timeout": 3000,
	})
	if r := ProbeWireGuard(string(raw)); !r.Alive {
		t.Fatalf("probe failed: %q", r.RespError)
	}
	settle(t, 0)
	after := goroutineDump()

	// The responder in this test legitimately runs device goroutines; what must
	// not happen is the probe adding more of them.
	for _, marker := range []string{"RoutineHandshake", "RoutineEncryption", "RoutineDecryption", "netstack", "gvisor"} {
		if strings.Count(after, marker) > strings.Count(before, marker) {
			t.Errorf("probe started a %q goroutine", marker)
		}
	}
}
