package fleet

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReportsBecomeOnlyBoundedDailyTotalsAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	reg, err := registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(24 * time.Hour)
	svc.now = func() time.Time { return now }
	report := fleetwire.Report{Schema: fleetwire.Schema, Version: "v0.146.0", Channel: "stable", Drivers: []string{}, Battery: "none", Zone: "SE4", Age: "unknown"}
	raw, _ := json.Marshal(report)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/v1/fleet", bytes.NewReader(raw))
			r.RemoteAddr = "198.51.100.8:443"
			svc.ServeHTTP(w, r)
			if w.Code != 204 {
				t.Errorf("status %d", w.Code)
			}
		})
	}
	wg.Wait()
	if err := reg.Close(); err != nil {
		t.Fatal(err)
	}
	reg, err = registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	svc, err = New(reg)
	if err != nil {
		t.Fatal(err)
	}
	view, err := reg.FleetView(now)
	if err != nil || len(view.Days) != 1 || view.Days[0].Reports != 100 {
		t.Fatal(view, err)
	}
	for i := 1; i < 92; i++ {
		if ok, err := reg.FleetPut(report, now.AddDate(0, 0, i)); err != nil || !ok {
			t.Fatal(err)
		}
	}
	view, _ = reg.FleetView(now.AddDate(0, 0, 91))
	if len(view.Days) != 90 {
		t.Fatal(len(view.Days))
	}
	// A long gap expires old populated dates, even without another report.
	if err := reg.FleetPrune(now.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	view, _ = reg.FleetView(now.AddDate(1, 0, 0))
	if len(view.Days) != 0 {
		t.Fatal("old totals survived", view)
	}
	for _, tc := range []struct {
		method, body string
		code         int
	}{{"GET", "", 405}, {"POST", `{"home":"x"}`, 400}, {"POST", string(make([]byte, 4097)), 413}} {
		w := httptest.NewRecorder()
		svc.ServeHTTP(w, httptest.NewRequest(tc.method, "/v1/fleet", bytes.NewBufferString(tc.body)))
		if w.Code != tc.code {
			t.Fatal(w.Code, tc)
		}
	}
	w := httptest.NewRecorder()
	svc.Stats(w, httptest.NewRequest(http.MethodGet, "/fleet/stats", nil))
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte("198.51.100")) {
		t.Fatal(w.Code, w.Body.String())
	}
	// The only extra table holds date and aggregate JSON, not source addresses.
}

// A sender that stops halfway through its body is cut off.
func TestASlowFleetBodyIsCutOff(t *testing.T) {
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	svc, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	old := bodyDeadline
	bodyDeadline = 200 * time.Millisecond
	t.Cleanup(func() { bodyDeadline = old })
	srv := httptest.NewServer(svc)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "POST /v1/fleet HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("slow body: %v %v", resp, err)
	}
}
