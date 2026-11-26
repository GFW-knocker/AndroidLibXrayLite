package libv2ray

// MeasureOutboundTransfer through a freedom outbound to a loopback server.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const transferCfg = `{"outbounds":[{"protocol":"freedom","tag":"direct"}],"dns":{"servers":["localhost"]}}`

type transferServer struct {
	*httptest.Server
	uploads  atomic.Int32 // POSTs that reached /up
	received atomic.Int64 // bytes the last /up read
}

func newTransferServer(t *testing.T) *transferServer {
	t.Helper()
	ts := &transferServer{}
	mux := http.NewServeMux()
	// /down?bytes=N[&pause=ms]: N bytes, with an optional pause halfway.
	mux.HandleFunc("/down", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("bytes"))
		pause, _ := strconv.Atoi(r.URL.Query().Get("pause"))
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.Write(make([]byte, n/2))
		w.(http.Flusher).Flush()
		time.Sleep(time.Duration(pause) * time.Millisecond)
		w.Write(make([]byte, n-n/2))
	})
	// /short: claims nothing, sends 10 bytes, so a bigger read must fail.
	mux.HandleFunc("/short", func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, 10))
	})
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		ts.uploads.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		ts.received.Store(n)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/up", http.StatusPermanentRedirect)
	})
	ts.Server = httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestMeasureOutboundTransferLocal(t *testing.T) {
	ts := newTransferServer(t)
	const size = 300 * 1024

	t.Run("download", func(t *testing.T) {
		ms, err := MeasureOutboundTransfer(transferCfg, ts.URL+"/down?bytes="+strconv.Itoa(size), size, "", 0, 10000)
		if err != nil || ms < 0 {
			t.Fatalf("= %d, %v", ms, err)
		}
	})
	t.Run("download counts the body, not just the headers", func(t *testing.T) {
		ms, err := MeasureOutboundTransfer(transferCfg, ts.URL+"/down?pause=400&bytes="+strconv.Itoa(size), size, "", 0, 10000)
		if err != nil || ms < 400 {
			t.Fatalf("= %d, %v; want >= 400 ms", ms, err)
		}
	})
	t.Run("upload sends exactly the size", func(t *testing.T) {
		ms, err := MeasureOutboundTransfer(transferCfg, "", 0, ts.URL+"/up", size, 10000)
		if err != nil || ms < 0 {
			t.Fatalf("= %d, %v", ms, err)
		}
		if got := ts.received.Load(); got != size {
			t.Fatalf("server got %d bytes, want %d", got, size)
		}
	})
	t.Run("both are summed", func(t *testing.T) {
		ms, err := MeasureOutboundTransfer(transferCfg, ts.URL+"/down?pause=300&bytes="+strconv.Itoa(size), size,
			ts.URL+"/up", size, 10000)
		if err != nil || ms < 300 {
			t.Fatalf("= %d, %v; want >= 300 ms", ms, err)
		}
	})
}

func TestMeasureOutboundTransferFailures(t *testing.T) {
	ts := newTransferServer(t)
	down := ts.URL + "/down?bytes=1000"

	for name, tc := range map[string]struct {
		cfg, downURL string
		downBytes    int64
		upURL        string
		upBytes      int64
		timeoutMs    int64
	}{
		"nothing to measure": {transferCfg, down, 0, ts.URL + "/up", 0, 5000},
		"no download url":    {transferCfg, "", 1000, "", 0, 5000},
		"no upload url":      {transferCfg, "", 0, "", 1000, 5000},
		"no timeout":         {transferCfg, down, 1000, "", 0, 0},
		"bad config":         {`{"outbounds":`, down, 1000, "", 0, 5000},
		"bad url":            {transferCfg, "http://exa mple.com/", 1000, "", 0, 5000},
		"short body":         {transferCfg, ts.URL + "/short", 1000, "", 0, 5000},
		"download status":    {transferCfg, ts.URL + "/fail", 1000, "", 0, 5000},
		"upload status":      {transferCfg, "", 0, ts.URL + "/fail", 1000, 5000},
		"redirect":           {transferCfg, "", 0, ts.URL + "/moved", 1000, 5000},
		"timeout":            {transferCfg, ts.URL + "/down?pause=3000&bytes=1000", 1000, "", 0, 500},
	} {
		t.Run(name, func(t *testing.T) {
			before := ts.uploads.Load()
			start := time.Now()
			ms, err := MeasureOutboundTransfer(tc.cfg, tc.downURL, tc.downBytes, tc.upURL, tc.upBytes, tc.timeoutMs)
			if err == nil || ms != -1 {
				t.Fatalf("= %d, %v; want -1 and an error", ms, err)
			}
			if name == "redirect" && ts.uploads.Load() != before {
				t.Errorf("the redirect was followed")
			}
			if name == "timeout" && time.Since(start) > 2*time.Second {
				t.Errorf("took %v with a 500 ms timeout", time.Since(start))
			}
		})
	}
}

// A cancel stops the calls running at that moment, at once, and only those.
func TestCancelOutboundTransfers(t *testing.T) {
	ts := newTransferServer(t)
	stalled := ts.URL + "/down?pause=3000&bytes=1000"

	const n = 3
	done := make(chan error, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		go func(i int) {
			var err error
			if i%2 == 0 {
				_, err = MeasureOutboundTransfer(transferCfg, stalled, 1000, "", 0, 10000)
			} else {
				_, err = MeasureOutboundTransfer(transferCfg, stalled, 1000, ts.URL+"/up", 1000, 10000)
			}
			done <- err
		}(i)
	}
	time.Sleep(300 * time.Millisecond)
	CancelOutboundTransfers()
	for i := 0; i < n; i++ {
		if err := <-done; err == nil || !strings.Contains(err.Error(), "canceled") {
			t.Errorf("call %d: err = %v, want canceled", i, err)
		}
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Errorf("canceled calls took %v to return (the server pauses 3 s)", took)
	}
	if ts.uploads.Load() != 0 {
		t.Errorf("an upload started after the canceled download")
	}

	// later calls run normally
	ms, err := MeasureOutboundTransfer(transferCfg, ts.URL+"/down?bytes=1000", 1000, ts.URL+"/up", 1000, 5000)
	if err != nil || ms < 0 {
		t.Fatalf("call after the cancel = %d, %v", ms, err)
	}
}

func TestRecoverToError(t *testing.T) {
	panics := func() (ms int64, err error) {
		defer recoverToError(&ms, &err)
		var m map[string]int
		m["x"] = 1 // nil map: panics
		return 5, nil
	}
	if ms, err := panics(); ms != -1 || err == nil || !strings.HasPrefix(err.Error(), "panic:") {
		t.Errorf("after a panic = %d, %v; want -1 and a panic error", ms, err)
	}

	fine := func() (ms int64, err error) {
		defer recoverToError(&ms, &err)
		return 5, nil
	}
	if ms, err := fine(); ms != 5 || err != nil {
		t.Errorf("without a panic = %d, %v; want 5, nil", ms, err)
	}
}

// A failed download must not be followed by an upload.
func TestMeasureOutboundTransferStopsAfterFailedDownload(t *testing.T) {
	ts := newTransferServer(t)
	ms, err := MeasureOutboundTransfer(transferCfg, ts.URL+"/short", 1000, ts.URL+"/up", 1000, 5000)
	if err == nil || !strings.HasPrefix(err.Error(), "download:") {
		t.Fatalf("= %d, %v; want a download error", ms, err)
	}
	if n := ts.uploads.Load(); n != 0 {
		t.Fatalf("upload ran %d times after a failed download", n)
	}
}
