package libv2ray

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	v2net "github.com/GFW-knocker/Xray-core/common/net"
	v2core "github.com/GFW-knocker/Xray-core/core"
	v2serial "github.com/GFW-knocker/Xray-core/infra/conf/serial"
)

// MeasureOutboundTransfer times a download and/or an upload through a config's
// outbound. Like MeasureOutboundDelay it starts a private core with no inbounds
// and the same reduced app set, so it works whether the VPN is running or not.
//
// A direction whose size is 0 or less is skipped; at least one must be set.
//   - download: GET downloadURL and read downloadBytes of its body. A body that
//     ends sooner is a failure; anything past downloadBytes is not read.
//   - upload: POST uploadBytes of random data to uploadURL (fixed length, not
//     chunked) and wait for the response.
//
// Each direction is one request on a new connection, timed from the start of
// the request (so the outbound's dial and the TLS handshake count, as they do
// in the delay test) until the last byte is read (download) or the response
// arrives (upload). Each must answer 200 and finish within timeoutMs.
//
// The result is the sum of the directions run, in ms. If one fails, the call
// fails, and the upload is not started after a failed download.
//
// CancelOutboundTransfers stops every call running at that moment.
func MeasureOutboundTransfer(ConfigureFileContent string, downloadURL string, downloadBytes int64,
	uploadURL string, uploadBytes int64, timeoutMs int64) (ms int64, err error) {
	defer recoverToError(&ms, &err)
	// taken before anything else, so a cancel from here on reaches this call
	parent := currentTransferContext()

	down := downloadBytes > 0
	up := uploadBytes > 0
	switch {
	case !down && !up:
		return -1, errors.New("nothing to measure")
	case down && downloadURL == "":
		return -1, errors.New("download url is empty")
	case up && uploadURL == "":
		return -1, errors.New("upload url is empty")
	case timeoutMs <= 0:
		return -1, errors.New("timeout must be positive")
	}
	if err := parent.Err(); err != nil {
		return -1, err // canceled already: don't start a core for nothing
	}

	config, err := v2serial.LoadJSONConfig(strings.NewReader(ConfigureFileContent))
	if err != nil {
		return -1, err
	}
	// same reduced instance as MeasureOutboundDelay
	config.Inbound = nil
	config.App = measureApps(config.App)

	inst, err := v2core.New(config)
	if err != nil {
		return -1, err
	}
	defer inst.Close()
	if err := inst.Start(); err != nil {
		return -1, err
	}

	client := transferClient(inst)
	timeout := time.Duration(timeoutMs) * time.Millisecond
	var total int64
	if down {
		took, err := timeDownload(parent, client, downloadURL, downloadBytes, timeout)
		if err != nil {
			return -1, fmt.Errorf("download: %w", err)
		}
		total += took
	}
	if up {
		took, err := timeUpload(parent, client, uploadURL, uploadBytes, timeout)
		if err != nil {
			return -1, fmt.Errorf("upload: %w", err)
		}
		total += took
	}
	return total, nil
}

// Every MeasureOutboundTransfer runs under the context that is current when it
// starts. CancelOutboundTransfers cancels that context and puts a fresh one in
// its place, so the calls running now stop and the ones started later don't.
var (
	transferMu                  sync.Mutex
	transferCtx, transferCancel = context.WithCancel(context.Background())
)

func currentTransferContext() context.Context {
	transferMu.Lock()
	defer transferMu.Unlock()
	return transferCtx
}

// CancelOutboundTransfers makes every MeasureOutboundTransfer running now fail
// at once (-1, "context canceled"), closing its connections. Calls started
// after it are not affected. It does no I/O, so any thread may call it.
func CancelOutboundTransfers() {
	transferMu.Lock()
	defer transferMu.Unlock()
	transferCancel()
	transferCtx, transferCancel = context.WithCancel(context.Background())
}

func transferClient(inst *v2core.Instance) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// The delay test's limit: a config that can't finish a TLS handshake
			// in 6 s fails here too, instead of waiting out the whole timeout.
			TLSHandshakeTimeout: 6 * time.Second,
			// A new connection per request, so each direction pays its own setup.
			DisableKeepAlives: true,
			// Measure the bytes as sent, not a gzip of them.
			DisableCompression: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest, err := v2net.ParseDestination(network + ":" + addr)
				if err != nil {
					return nil, err
				}
				return v2core.Dial(ctx, inst, dest)
			},
		},
		// A redirect means a wrong URL. Following it would hide that, and a
		// 307/308 would send the whole upload a second time.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func timeDownload(parent context.Context, client *http.Client, rawURL string, size int64, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return -1, err
	}
	req.Header.Set("Accept-Encoding", "identity")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("status %s", resp.Status)
	}
	n, err := io.CopyN(io.Discard, resp.Body, size)
	if err == io.EOF {
		err = fmt.Errorf("body ended after %d of %d bytes", n, size)
	}
	if err != nil {
		return -1, err
	}
	return time.Since(start).Milliseconds(), nil
}

func timeUpload(parent context.Context, client *http.Client, rawURL string, size int64, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, io.LimitReader(newRepeatReader(), size))
	if err != nil {
		return -1, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1, err
	}
	elapsed := time.Since(start).Milliseconds()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("status %s", resp.Status)
	}
	// The reply is small; it is drained outside the timing.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return elapsed, nil
}

// repeatReader never ends: it serves one 64 KiB block of random bytes over and
// over. Random so nothing on the way can compress it, one block so a 500 KB
// upload doesn't need 500 KB of fresh randomness.
type repeatReader struct {
	block []byte
	off   int
}

func newRepeatReader() *repeatReader {
	block := make([]byte, 64<<10)
	crand.Read(block)
	return &repeatReader{block: block}
}

func (r *repeatReader) Read(p []byte) (int, error) {
	n := copy(p, r.block[r.off:])
	r.off = (r.off + n) % len(r.block)
	return n, nil
}
