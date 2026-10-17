package statistics

import (
	"bytes"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

func TestCollectionOffByDefaultCannotLookLikeZeroUsage(t *testing.T) {
	r, err := registry.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/v1/stats", nil))
	if w.Code != 503 || w.Header().Get("FTW-Statistics-State") != "disabled" {
		t.Fatalf("disabled collection pretended to be zero usage: %d", w.Code)
	}
	s.Enabled = true
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/v1/stats", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestStartupPrunesOldHoursEvenWithCollectionDisabled(t *testing.T) {
	r, err := registry.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-72 * time.Hour)
	for home, clock := range map[string]time.Time{"old": old, "recent": now} {
		if err := r.Claim(home, []byte("key"), clock); err != nil {
			t.Fatal(err)
		}
		g := cloudwire.Grant{TermsPolicy: cloudwire.CloudTermsPolicy, Controller: cloudwire.ControllerSourceful, Purposes: []string{protocol.CloudPurposeServe, protocol.CloudPurposeStats}, StatsID: bytes.Repeat([]byte{1}, 16), StatsPolicy: cloudwire.StatsPolicy, StatsSinceMs: clock.Add(-2 * time.Hour).UnixMilli()}
		if err := r.StatisticsGrant(home, g); err != nil {
			t.Fatal(err)
		}
		if err := r.StatisticsPut(home, cloudwire.Stats{StatsID: g.StatsID, Policy: g.StatsPolicy, HourMS: clock.Truncate(time.Hour).Add(-time.Hour).UnixMilli(), Metrics: map[string]int64{"pv_generation_wh": 100}}, clock); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(r)
	if err != nil || s.Enabled {
		t.Fatal("startup failed or enabled collection", err)
	}
	v, err := r.StatisticsView(old)
	if err != nil || v.Installations.State != "empty" {
		t.Fatal("startup kept expired hours", err)
	}
	v, err = r.StatisticsView(now)
	if err != nil || v.Installations.State != "withheld" {
		t.Fatal("startup removed recent hours", err)
	}
}
