package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// TestOnceReadTimes measures the watch's one-shot read, from the first byte
// the watch sends to the answer decrypted, over HTTP/1.1 (what TCP serves
// today), HTTP/2 and HTTP/3. Cold is a new connection per read, as after
// the watch slept; warm reuses one. It runs only when FTW_BENCH_ONCE names
// the reads per row, because the numbers mean something only on a link
// with delay and loss. scripts/netem-once.sh runs it under netem.
func TestOnceReadTimes(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("FTW_BENCH_ONCE"))
	if n <= 0 {
		t.Skip("set FTW_BENCH_ONCE to the reads per row")
	}
	s := newStack(t)
	box := s.connectBox()
	// A device may read 30 times a minute, so the reads go round many
	// watches.
	var watches []appwire.KeyPair
	var devices []cloudwire.Device
	for i := range 48 {
		k, _ := appwire.GenerateKeyPair()
		watches = append(watches, k)
		devices = append(devices, cloudwire.Device{ID: fmt.Sprintf("watch%02d", i), Key: k.Public(), Role: "watch",
			Scopes: []string{protocol.ScopeLiveRead, protocol.ScopePlanRead, protocol.ScopeEventsRead}, Epoch: 1})
	}
	box.roster(1, devices...)
	box.live(true)
	box.hb()
	waitHeld(t, s.st, box.home, watches[0], 2)

	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	tlsConf := func() *tls.Config {
		return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	}

	// HTTP/2 beside the service's own HTTP/1.1, for comparison only: the
	// service does not offer it on TCP, because its sockets are HTTP/1.1.
	h2 := httptest.NewUnstartedServer(s.srv.Config.Handler)
	h2.EnableHTTP2 = true
	h2.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: s.srv.TLS.Certificates}
	h2.StartTLS()
	defer h2.Close()
	_, h3base := s.h3()

	type row struct {
		name  string
		proto int
		base  string
		// client returns a client for one read; cold ones are new each time.
		client func() (*http.Client, func())
	}
	tcp := func(base string, h2 bool, cold bool) func() (*http.Client, func()) {
		var shared *http.Transport
		mk := func() *http.Transport {
			tr := &http.Transport{TLSClientConfig: tlsConf(), ForceAttemptHTTP2: h2, DialContext: (&net.Dialer{}).DialContext}
			if !h2 {
				tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
			}
			return tr
		}
		return func() (*http.Client, func()) {
			if cold {
				tr := mk()
				return &http.Client{Transport: tr}, tr.CloseIdleConnections
			}
			if shared == nil {
				shared = mk()
			}
			return &http.Client{Transport: shared}, func() {}
		}
	}
	quic := func(cold bool) func() (*http.Client, func()) {
		var shared *http3.Transport
		return func() (*http.Client, func()) {
			if cold {
				tr := &http3.Transport{TLSClientConfig: tlsConf()}
				return &http.Client{Transport: tr}, func() { _ = tr.Close() }
			}
			if shared == nil {
				shared = &http3.Transport{TLSClientConfig: tlsConf()}
			}
			return &http.Client{Transport: shared}, func() {}
		}
	}
	rows := []row{
		{"HTTP/1.1 cold", 1, s.srv.URL, tcp(s.srv.URL, false, true)},
		{"HTTP/2 cold", 2, h2.URL, tcp(h2.URL, true, true)},
		{"HTTP/3 cold", 3, h3base, quic(true)},
		{"HTTP/1.1 warm", 1, s.srv.URL, tcp(s.srv.URL, false, false)},
		{"HTTP/2 warm", 2, h2.URL, tcp(h2.URL, true, false)},
		{"HTTP/3 warm", 3, h3base, quic(false)},
	}
	label := os.Getenv("FTW_BENCH_LABEL")
	fmt.Printf("| link | read | n | p50 ms | p95 ms | max ms | failed |\n|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		var took []time.Duration
		failed := 0
		for i := range n {
			c, done := r.client()
			c.Timeout = 10 * time.Second
			w := &watchClient{t: t, http: c, base: r.base, key: watches[i%len(watches)], service: s.noise.Public(), home: box.home}
			start := time.Now()
			proto, ok := w.tryRead()
			if ok && proto != r.proto {
				t.Fatalf("%s went over HTTP/%d", r.name, proto)
			}
			if ok {
				took = append(took, time.Since(start))
			} else {
				failed++
			}
			done()
			// The service holds one read per device at a time and a
			// number per minute; the watch glances, it does not stream.
			time.Sleep(20 * time.Millisecond)
		}
		slices.Sort(took)
		q := func(p float64) float64 {
			if len(took) == 0 {
				return 0
			}
			return float64(took[min(len(took)-1, int(p*float64(len(took))))].Microseconds()) / 1000
		}
		fmt.Printf("| %s | %s | %d | %.0f | %.0f | %.0f | %d |\n", label, r.name, len(took), q(0.5), q(0.95), q(1), failed)
	}
}

// tryRead is one read that reports failure instead of ending the test, so
// a read lost on a bad link counts as lost.
func (w *watchClient) tryRead() (proto int, ok bool) {
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: w.key, RemoteStatic: w.service,
		Prologue: cloudwire.OncePrologue(w.home)})
	if err != nil {
		return 0, false
	}
	payload, _ := cloudwire.Unsigned(cloudwire.MsgRead, cloudwire.Read{Hz: cloudwire.HzAway})
	msg1, err := init.WriteMessage(payload)
	if err != nil {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, w.base+cloudwire.OncePath+"?"+cloudwire.AppHomeParam+"="+w.home,
		bytes.NewReader(msg1))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := w.http.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	answer := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for {
		k, err := resp.Body.Read(buf)
		answer = append(answer, buf[:k]...)
		if err != nil {
			break
		}
	}
	if resp.StatusCode != http.StatusOK {
		return resp.ProtoMajor, false
	}
	parts, err := cloudwire.SplitOnceAnswer(answer)
	if err != nil {
		return resp.ProtoMajor, false
	}
	_, err = init.ReadMessage(parts[0])
	return resp.ProtoMajor, err == nil
}
