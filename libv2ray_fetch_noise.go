package libv2ray

// QUIC noise for the h3 path: a handful of junk UDP datagrams sent on the
// handshake's own socket, just before the ClientHello.
//
// Why it helps: some networks decide whether to drop a UDP flow from the very
// first datagram they see on it, and then cache that verdict for the 4-tuple.
// A QUIC v1 Initial trips the filter; a datagram carrying any other version
// number does not. Sending one of the latter first files the flow as
// uninteresting, so the real handshake that follows rides through on a verdict
// that was already taken. The corollary matters as much: a flow that *leads*
// with v1 stays poisoned, so noise is only ever useful before the first real
// packet, never after.
//
// The packet shapes and the option vocabulary are xray-core's WireGuard noise
// (proxy/wireguard/client.go plus wireguard device/send.go), so a wnoise value
// that works in a WireGuard outbound works here unchanged.
//
// One deliberate divergence: xray silently ignores a malformed wnoise hex
// string and sends nothing. Here it is an error, because silently sending no
// noise looks exactly like noise that did not help.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
)

// Named wnoise presets. Anything else is read as a hex header.
const (
	noiseNone   = "none"
	noiseQUIC   = "quic"   // QUIC v2, RFC 9369
	noiseQUICv1 = "quicv1" // QUIC v1, RFC 9000
	noiseRandom = "random"
)

// Ceilings, matching xray's. They exist so a typo cannot turn into a long
// stall or a flood: the whole noise burst is paid for before the request runs.
const (
	noiseMaxCount     = 50
	noiseMaxDelayMs   = 100
	noiseMaxPayload   = 100
	noiseMaxHeaderLen = 50 // bytes, i.e. xray's 100-hex-character cap
)

// Version fields the "quic" presets put in bytes 1..4, which is the only part
// of the header the filters this defeats are known to read.
var (
	quicNoiseVersion2 = []byte{0x6B, 0x33, 0x43, 0xCF} // RFC 9369
	quicNoiseVersion1 = []byte{0x00, 0x00, 0x00, 0x01} // RFC 9000
)

type noiseConfig struct {
	// One of the preset names, or "hex" when header is set.
	mode   string
	header []byte // custom header, nil for the presets

	countFrom, countTo int
	delayFrom, delayTo int // milliseconds
	sizeFrom, sizeTo   int // payload bytes appended after the header
}

// noiseRand returns a uniform int in [min, max], inclusive at both ends like
// xray's randomInt. Falls back to min rather than panicking, so a starved
// entropy pool degrades to fixed-shape noise instead of killing the request.
func noiseRand(min, max int) int {
	if min > max {
		min, max = max, min
	}
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return int(n.Int64()) + min
}

// parseNoiseRange reads "n" or "from-to", both inclusive. An empty string takes
// the default. Values above limit are clamped rather than rejected, matching
// xray, so a config written for a future higher ceiling still runs.
func parseNoiseRange(value, name string, defFrom, defTo, limit int) (int, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defFrom, defTo, nil
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 {
		return 0, 0, fmt.Errorf("%s %q must be a number or a \"from-to\" range", name, value)
	}
	bounds := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || v < 0 {
			return 0, 0, fmt.Errorf("%s %q must be a non-negative number or a \"from-to\" range", name, value)
		}
		bounds[i] = v
	}
	from, to := bounds[0], bounds[0]
	if len(bounds) == 2 {
		to = bounds[1]
	}
	if from > to {
		from, to = to, from
	}
	if from > limit {
		from = limit
	}
	if to > limit {
		to = limit
	}
	return from, to, nil
}

// noiseConfig builds the noise plan, or nil when noise is off. The ranges are
// parsed either way, so a typo in wnoisecount surfaces even if the caller has
// not enabled noise yet.
func (o *transportOptions) noiseConfig() (*noiseConfig, error) {
	n := &noiseConfig{mode: strings.ToLower(strings.TrimSpace(o.WNoise))}

	var err error
	if n.countFrom, n.countTo, err = parseNoiseRange(o.WNoiseCount, "wnoisecount", 5, 5, noiseMaxCount); err != nil {
		return nil, err
	}
	if n.delayFrom, n.delayTo, err = parseNoiseRange(o.WNoiseDelay, "wnoisedelay", 5, 5, noiseMaxDelayMs); err != nil {
		return nil, err
	}
	if n.sizeFrom, n.sizeTo, err = parseNoiseRange(o.WPayloadSize, "wpayloadsize", 5, 10, noiseMaxPayload); err != nil {
		return nil, err
	}

	switch n.mode {
	case "", noiseNone:
		return nil, nil
	case noiseQUIC, noiseQUICv1, noiseRandom:
		return n, nil
	}

	// Anything else is a custom header, given as hex.
	if len(n.mode)%2 != 0 {
		return nil, fmt.Errorf("wnoise %q has an odd number of hex digits: give whole bytes, "+
			"or use \"none\", \"quic\", \"quicv1\" or \"random\"", o.WNoise)
	}
	header, err := hex.DecodeString(n.mode)
	if err != nil {
		return nil, fmt.Errorf("wnoise %q is neither a preset (\"none\", \"quic\", \"quicv1\", "+
			"\"random\") nor a hex string: %w", o.WNoise, err)
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("wnoise is empty: use \"none\" to disable noise")
	}
	if len(header) > noiseMaxHeaderLen {
		return nil, fmt.Errorf("wnoise is %d bytes, more than the %d-byte maximum",
			len(header), noiseMaxHeaderLen)
	}
	n.mode, n.header = "hex", header
	return n, nil
}

// quicNoiseHeader builds the 18-byte pseudo-QUIC long header xray sends.
//
// It is not a valid packet and does not need to be: the length varint claims
// 1232 bytes with nothing like that many following. What it carries is a
// version number in bytes 1..4 and enough of a long header in front of it to
// get that far.
func quicNoiseHeader(version []byte) []byte {
	// The first byte's high nibble names a long-header packet type, and its low
	// nibble is header-protected in a real packet. The type is irrelevant to
	// the filters this defeats, so it is drawn from xray's list rather than
	// fixed, to avoid handing anyone a constant byte to match on.
	clist := []byte{0xDC, 0xDE, 0xD3, 0xD9, 0xD0, 0xEC, 0xEE, 0xE3}

	dcid := make([]byte, 8)
	if _, err := rand.Read(dcid); err != nil {
		return nil
	}
	h := make([]byte, 0, 18)
	h = append(h, clist[noiseRand(0, len(clist)-1)])
	h = append(h, version...)
	h = append(h, 0x08) // DCID length
	h = append(h, dcid...)
	h = append(h, 0x00, 0x00, 0x44, 0xD0) // SCID length, token length, length varint
	return h
}

// nextHeader returns the header for one datagram. The presets re-roll per
// packet, so a burst is not the same bytes repeated.
func (n *noiseConfig) nextHeader() []byte {
	switch n.mode {
	case noiseQUIC:
		return quicNoiseHeader(quicNoiseVersion2)
	case noiseQUICv1:
		return quicNoiseHeader(quicNoiseVersion1)
	case noiseRandom:
		h := make([]byte, 18)
		if _, err := rand.Read(h); err != nil {
			return nil
		}
		return h
	default:
		return n.header
	}
}

// send writes the noise burst to dst.
//
// pc must be the socket the handshake will use, and this must run before the
// first handshake packet: the point is for these to be the opening datagrams
// of the 4-tuple. Sending them anywhere else is wasted traffic.
func (n *noiseConfig) send(ctx context.Context, pc *net.UDPConn, dst *net.UDPAddr) error {
	count := noiseRand(n.countFrom, n.countTo)
	for i := 0; i < count; i++ {
		header := n.nextHeader()
		if header == nil {
			return fmt.Errorf("wnoise: cannot read random bytes")
		}
		size := noiseRand(n.sizeFrom, n.sizeTo)
		packet := make([]byte, len(header)+size)
		copy(packet, header)
		if size > 0 {
			if _, err := rand.Read(packet[len(header):]); err != nil {
				return fmt.Errorf("wnoise: cannot read random bytes: %w", err)
			}
		}
		if _, err := pc.WriteToUDP(packet, dst); err != nil {
			return fmt.Errorf("wnoise: cannot send noise to %s: %w", dst, err)
		}
		// Pause after every packet, the last one included: the gap before the
		// handshake is what gives an on-path classifier time to file the flow.
		delay := noiseRand(n.delayFrom, n.delayTo)
		if delay == 0 {
			continue
		}
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return nil
}
