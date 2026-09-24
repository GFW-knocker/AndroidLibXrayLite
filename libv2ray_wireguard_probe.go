package libv2ray

// ProbeWireGuard: ask a UDP endpoint to prove it is the WireGuard peer we think
// it is, optionally after priming the socket with noise.
//
// There is no certificate here and nothing to read off the wire that a filter
// could not forge: the proof is the handshake itself. We send a Noise IKpsk2
// initiation addressed to a specific static public key, and only the holder of
// the matching private key can produce a response whose empty payload
// authenticates. A middlebox that answers to look busy fails that test.
//
// Everything cryptographic is borrowed from the WireGuard implementation the
// core already links -- its constants, its KDFs, its message layouts, its MAC
// generator -- so this cannot drift from what the tunnel itself does. What is
// written here is only the initiator half of the handshake, which that package
// keeps unexported behind a Device.
//
// The reserved bytes carry Cloudflare's client_id: WARP puts it in the three
// bytes after the message type, where vanilla WireGuard has zeros.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/GFW-knocker/wireguard/device"
	"github.com/GFW-knocker/wireguard/tai64n"
)

// WireGuardResult is the result of ProbeWireGuard.
type WireGuardResult struct {
	// Alive is the verdict: a handshake response arrived and authenticated
	// against the public key that was probed. Nothing else proves the peer.
	Alive bool
	// Responded is true when any datagram came back at all. Alive false with
	// Responded true is the interesting case -- something is there, but it is
	// not the peer we asked for, or it refused us.
	Responded bool
	// ReplyType is the WireGuard message type of the last datagram received:
	// 2 is a handshake response, 3 a cookie reply (the peer is real but wants
	// mac2, which means it is under load), 0 none.
	ReplyType int
	ReplySize int
	// Attempts is how many initiations were sent before giving up or winning.
	Attempts int
	RttMs    int
	// RespError is empty when Alive is true.
	RespError string
}

// wireGuardProbeOptions is what ProbeWireGuard accepts.
//
// The noise fields use exactly the vocabulary of an xray WireGuard outbound's
// wnoise, so values can be copied across unchanged.
type wireGuardProbeOptions struct {
	// Address is "host:port" of the endpoint to probe.
	Address string `json:"address"`
	// IP pins the address to dial, leaving Address to name the endpoint.
	IP string `json:"ip"`
	// PublicKey is the peer's static public key, base64, 32 bytes. Required:
	// it is what the response is checked against.
	PublicKey string `json:"publicKey"`
	// PrivateKey is our own static private key, base64.
	//
	// In practice this is required. A responder decrypts the initiator's static
	// key and looks it up among its configured peers; one it does not know is
	// dropped without a reply, so a probe carrying a random key cannot tell a
	// live endpoint from a dead one. Pass the key of a registered account --
	// for WARP, the one the generator produced. A random key is generated when
	// this is empty, which is only useful against a peer that already knows it.
	PrivateKey string `json:"privateKey"`
	// PresharedKey is the optional psk, base64.
	PresharedKey string `json:"presharedKey"`
	// Reserved is Cloudflare's client_id: "1,2,3" or the base64 of 3 bytes.
	// Empty means zeros, which is what vanilla WireGuard expects.
	Reserved string `json:"reserved"`
	// Timeout for the whole probe, in milliseconds, split across the attempts.
	Timeout int `json:"timeout"`
	// Attempts is how many initiations to send before calling it dead. Each one
	// is built fresh, because a peer discards a repeated timestamp as a replay.
	// Default 2: a single lost datagram should not condemn an endpoint.
	Attempts int `json:"attempts"`

	WNoise       string `json:"wnoise"`
	WNoiseCount  string `json:"wnoisecount"`
	WNoiseDelay  string `json:"wnoisedelay"`
	WPayloadSize string `json:"wpayloadsize"`
}

func (o *wireGuardProbeOptions) timeout() time.Duration {
	if o.Timeout <= 0 {
		return defaultTimeoutMs * time.Millisecond
	}
	return time.Duration(o.Timeout) * time.Millisecond
}

func (o *wireGuardProbeOptions) attempts() int {
	if o.Attempts <= 0 {
		return 2
	}
	return o.Attempts
}

// noise reuses the fetch path's noise builder, so the presets, the ranges and
// their limits are the same ones the h3 probe and FetchWeb use.
func (o *wireGuardProbeOptions) noise() (*noiseConfig, error) {
	t := &transportOptions{
		WNoise:       o.WNoise,
		WNoiseCount:  o.WNoiseCount,
		WNoiseDelay:  o.WNoiseDelay,
		WPayloadSize: o.WPayloadSize,
	}
	return t.noiseConfig()
}

// ProbeWireGuard sends a handshake initiation and reports whether the endpoint
// answered as the peer it claims to be.
//
//	{"address":"162.159.192.1:2408",
//	 "publicKey":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
//	 "privateKey":"<the account's own key>",
//	 "reserved":"0,0,0", "timeout":5000,
//	 "wnoise":"quic", "wnoisecount":"5", "wnoisedelay":"5"}
//
// A silent endpoint is reported as not alive rather than as an error: on this
// protocol there is no difference between a port that is filtered, a peer that
// does not know the key it was addressed with, and one that is simply down.
func ProbeWireGuard(optionsJSON string) *WireGuardResult {
	opts := &wireGuardProbeOptions{}
	if err := json.Unmarshal([]byte(optionsJSON), opts); err != nil {
		return &WireGuardResult{RespError: "invalid options json: " + err.Error()}
	}
	if opts.Address == "" {
		return &WireGuardResult{RespError: "address is required"}
	}
	host, port, err := net.SplitHostPort(opts.Address)
	if err != nil {
		return &WireGuardResult{RespError: fmt.Sprintf("address %q is not host:port: %v", opts.Address, err)}
	}
	if opts.IP != "" {
		if net.ParseIP(opts.IP) == nil {
			return &WireGuardResult{RespError: fmt.Sprintf("ip %q is not a valid IP address", opts.IP)}
		}
		host = opts.IP
	}

	peerPublic, err := parseNoiseKey(opts.PublicKey, "publicKey")
	if err != nil {
		return &WireGuardResult{RespError: err.Error()}
	}
	var ourPrivate device.NoisePrivateKey
	if opts.PrivateKey == "" {
		if err := randomNoisePrivateKey(&ourPrivate); err != nil {
			return &WireGuardResult{RespError: err.Error()}
		}
	} else {
		key, err := parseNoiseKey(opts.PrivateKey, "privateKey")
		if err != nil {
			return &WireGuardResult{RespError: err.Error()}
		}
		ourPrivate = device.NoisePrivateKey(key)
		clampPrivateKey(&ourPrivate)
	}
	var psk device.NoisePresharedKey
	if opts.PresharedKey != "" {
		key, err := parseNoiseKey(opts.PresharedKey, "presharedKey")
		if err != nil {
			return &WireGuardResult{RespError: err.Error()}
		}
		psk = device.NoisePresharedKey(key)
	}
	reserved, err := parseReserved(opts.Reserved)
	if err != nil {
		return &WireGuardResult{RespError: err.Error()}
	}
	noise, err := opts.noise()
	if err != nil {
		return &WireGuardResult{RespError: err.Error()}
	}

	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port))
	if err != nil {
		return &WireGuardResult{RespError: fmt.Sprintf("cannot resolve %q: %v", opts.Address, err)}
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return &WireGuardResult{RespError: "cannot open udp socket: " + err.Error()}
	}
	defer conn.Close()

	total := opts.timeout()
	attempts := opts.attempts()
	ctx, cancel := context.WithTimeout(context.Background(), total)
	defer cancel()

	// The noise goes out once, before the first initiation and never after: the
	// filters it is aimed at judge a flow on its opening datagram and then stop
	// looking, so repeating it per attempt would only add delay.
	if noise != nil {
		if err := noise.send(ctx, conn, udpAddr); err != nil {
			return &WireGuardResult{RespError: err.Error()}
		}
	}

	result := &WireGuardResult{}
	started := time.Now()
	per := total / time.Duration(attempts)
	for i := 0; i < attempts; i++ {
		result.Attempts = i + 1
		err := probeWireGuardOnce(conn, udpAddr, ourPrivate, peerPublic, psk, reserved, per, result)
		result.RttMs = int(time.Since(started).Milliseconds())
		if result.Alive {
			result.RespError = ""
			return result
		}
		if err != nil {
			result.RespError = err.Error()
		}
		if ctx.Err() != nil {
			break
		}
	}
	if result.RespError == "" {
		result.RespError = "no handshake response"
	}
	return result
}

// probeWireGuardOnce builds one initiation, sends it, and waits for a response
// that authenticates. Anything else received is recorded and ignored.
func probeWireGuardOnce(
	conn *net.UDPConn,
	dst *net.UDPAddr,
	ourPrivate device.NoisePrivateKey,
	peerPublic device.NoisePublicKey,
	psk device.NoisePresharedKey,
	reserved [3]byte,
	wait time.Duration,
	result *WireGuardResult,
) error {
	hs, packet, err := createInitiation(ourPrivate, peerPublic, reserved)
	if err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(packet, dst); err != nil {
		return fmt.Errorf("cannot send the handshake initiation to %s: %w", dst, err)
	}

	deadline := time.Now().Add(wait)
	buf := make([]byte, 1500)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// Out of time for this attempt. Not worth reporting as an
				// error: silence is the ordinary answer here, and the raw
				// message would only name our own socket.
				return nil
			}
			return err
		}
		// Only the endpoint being probed counts; a stray datagram from
		// somewhere else says nothing about it.
		if !from.IP.Equal(dst.IP) || from.Port != dst.Port {
			continue
		}
		result.Responded = true
		result.ReplySize = n
		if n >= 1 {
			result.ReplyType = int(buf[0])
		}
		if n != device.MessageResponseSize || result.ReplyType != device.MessageResponseType {
			// A cookie reply (type 3) means the peer is real but wants mac2.
			// Keep listening: the real response may still be in flight.
			continue
		}
		ok, err := consumeResponse(hs, buf[:n], ourPrivate, psk)
		if err != nil {
			return err
		}
		if ok {
			result.Alive = true
			return nil
		}
		// Not ours, or not from the key we asked for. Keep waiting.
	}
}

// initiatorState is what has to survive between sending the initiation and
// reading the response.
type initiatorState struct {
	hash           [blake2s.Size]byte
	chainKey       [blake2s.Size]byte
	localEphemeral device.NoisePrivateKey
	localIndex     uint32
}

// createInitiation is device.CreateMessageInitiation without the Device: same
// steps, same order, using that package's own constants and KDFs.
func createInitiation(
	ourPrivate device.NoisePrivateKey,
	peerPublic device.NoisePublicKey,
	reserved [3]byte,
) (*initiatorState, []byte, error) {
	hs := &initiatorState{
		hash:     device.InitialHash,
		chainKey: device.InitialChainKey,
	}
	if err := randomNoisePrivateKey(&hs.localEphemeral); err != nil {
		return nil, nil, err
	}
	ourPublic, err := publicKeyOf(ourPrivate)
	if err != nil {
		return nil, nil, err
	}
	ephemeralPublic, err := publicKeyOf(hs.localEphemeral)
	if err != nil {
		return nil, nil, err
	}

	mixHashInto(&hs.hash, &hs.hash, peerPublic[:])

	msg := device.MessageInitiation{
		Type:      device.MessageInitiationType,
		Ephemeral: ephemeralPublic,
	}

	device.KDF1(&hs.chainKey, hs.chainKey[:], msg.Ephemeral[:])
	mixHashInto(&hs.hash, &hs.hash, msg.Ephemeral[:])

	// encrypt our static public key under the ephemeral-to-static secret
	ss, err := sharedSecret(hs.localEphemeral, peerPublic)
	if err != nil {
		return nil, nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	device.KDF2(&hs.chainKey, &key, hs.chainKey[:], ss[:])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, err
	}
	aead.Seal(msg.Static[:0], device.ZeroNonce[:], ourPublic[:], hs.hash[:])
	mixHashInto(&hs.hash, &hs.hash, msg.Static[:])

	// encrypt the timestamp under the static-to-static secret
	staticStatic, err := sharedSecret(ourPrivate, peerPublic)
	if err != nil {
		return nil, nil, err
	}
	device.KDF2(&hs.chainKey, &key, hs.chainKey[:], staticStatic[:])
	aead, err = chacha20poly1305.New(key[:])
	if err != nil {
		return nil, nil, err
	}
	timestamp := tai64n.Now()
	aead.Seal(msg.Timestamp[:0], device.ZeroNonce[:], timestamp[:], hs.hash[:])

	// Any index will do: nothing else is using this socket, and the responder
	// only echoes it back so we can recognise our own response.
	var indexBytes [4]byte
	if err := randomBytes(indexBytes[:]); err != nil {
		return nil, nil, err
	}
	msg.Sender = binary.LittleEndian.Uint32(indexBytes[:])
	hs.localIndex = msg.Sender

	mixHashInto(&hs.hash, &hs.hash, msg.Timestamp[:])

	var writer bytes.Buffer
	if err := binary.Write(&writer, binary.LittleEndian, &msg); err != nil {
		return nil, nil, err
	}
	packet := writer.Bytes()
	if len(packet) != device.MessageInitiationSize {
		return nil, nil, fmt.Errorf("built a %d byte initiation, want %d",
			len(packet), device.MessageInitiationSize)
	}

	// mac1 over everything before it; mac2 stays zero until a cookie arrives.
	var cookie device.CookieGenerator
	cookie.Init(peerPublic)
	cookie.AddMacs(packet)

	// The client_id goes where the type's padding is, after the MACs are
	// computed: the peer strips these bytes before it checks mac1.
	packet[1], packet[2], packet[3] = reserved[0], reserved[1], reserved[2]
	return hs, packet, nil
}

// consumeResponse is the initiator half of device.ConsumeMessageResponse: it
// finishes the three-way DH and opens the empty payload. Only the holder of the
// peer's private key can produce one that opens.
func consumeResponse(
	hs *initiatorState,
	packet []byte,
	ourPrivate device.NoisePrivateKey,
	psk device.NoisePresharedKey,
) (bool, error) {
	var msg device.MessageResponse
	// The reserved bytes are the peer's, not part of the type, so mask them off
	// the same way the receive path does before it reads the message.
	clean := make([]byte, len(packet))
	copy(clean, packet)
	clean[1], clean[2], clean[3] = 0, 0, 0
	if err := binary.Read(bytes.NewReader(clean), binary.LittleEndian, &msg); err != nil {
		return false, err
	}
	if msg.Receiver != hs.localIndex {
		// A response to somebody else's handshake, or to an earlier attempt.
		return false, nil
	}

	var hash [blake2s.Size]byte
	var chainKey [blake2s.Size]byte
	mixHashInto(&hash, &hs.hash, msg.Ephemeral[:])
	device.KDF1(&chainKey, hs.chainKey[:], msg.Ephemeral[:])

	ss, err := sharedSecret(hs.localEphemeral, msg.Ephemeral)
	if err != nil {
		return false, nil
	}
	device.KDF1(&chainKey, chainKey[:], ss[:])

	ss, err = sharedSecret(ourPrivate, msg.Ephemeral)
	if err != nil {
		return false, nil
	}
	device.KDF1(&chainKey, chainKey[:], ss[:])

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	device.KDF3(&chainKey, &tau, &key, chainKey[:], psk[:])
	mixHashInto(&hash, &hash, tau[:])

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false, err
	}
	if _, err := aead.Open(nil, device.ZeroNonce[:], msg.Empty[:], hash[:]); err != nil {
		// The one verdict that matters: whoever answered does not hold the
		// private key for the public key we addressed.
		return false, nil
	}
	return true, nil
}

// mixHashInto is the unexported mixHash of the device package: BLAKE2s over the
// running hash and the new data.
func mixHashInto(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
}

func sharedSecret(private device.NoisePrivateKey, public device.NoisePublicKey) ([32]byte, error) {
	var out [32]byte
	secret, err := curve25519.X25519(private[:], public[:])
	if err != nil {
		return out, fmt.Errorf("invalid key material: %w", err)
	}
	copy(out[:], secret)
	return out, nil
}

func publicKeyOf(private device.NoisePrivateKey) (device.NoisePublicKey, error) {
	var out device.NoisePublicKey
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return out, fmt.Errorf("invalid private key: %w", err)
	}
	copy(out[:], public)
	return out, nil
}

func randomBytes(b []byte) error {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return fmt.Errorf("cannot read random bytes: %w", err)
	}
	return nil
}

func clampPrivateKey(key *device.NoisePrivateKey) {
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
}

func randomNoisePrivateKey(key *device.NoisePrivateKey) error {
	if err := randomBytes(key[:]); err != nil {
		return err
	}
	clampPrivateKey(key)
	return nil
}

// parseNoiseKey reads a base64 32-byte key, in either alphabet, padded or not.
func parseNoiseKey(value, field string) (device.NoisePublicKey, error) {
	var key device.NoisePublicKey
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return key, fmt.Errorf("%s is required", field)
	}
	raw, err := decodeBase64Any(trimmed)
	if err != nil {
		return key, fmt.Errorf("%s is not valid base64: %w", field, err)
	}
	if len(raw) != device.NoisePublicKeySize {
		return key, fmt.Errorf("%s is %d bytes, want %d", field, len(raw), device.NoisePublicKeySize)
	}
	copy(key[:], raw)
	return key, nil
}

// parseReserved accepts "1,2,3" or the base64 of exactly three bytes, which is
// how a WARP client_id is usually written.
func parseReserved(value string) ([3]byte, error) {
	var out [3]byte
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return out, nil
	}
	if strings.Contains(trimmed, ",") {
		parts := strings.Split(trimmed, ",")
		if len(parts) != 3 {
			return out, fmt.Errorf("reserved %q has %d values, want 3", value, len(parts))
		}
		for i, part := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 0 || n > 255 {
				return out, fmt.Errorf("reserved %q is not three values in 0-255", value)
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	raw, err := decodeBase64Any(trimmed)
	if err != nil {
		return out, fmt.Errorf("reserved %q is neither \"a,b,c\" nor base64: %w", value, err)
	}
	if len(raw) != 3 {
		return out, fmt.Errorf("reserved decodes to %d bytes, want 3", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func decodeBase64Any(value string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(value); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("cannot decode %q", value)
}
