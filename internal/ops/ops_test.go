package ops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/fleet"
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

const key = "a-test-key-of-forty-three-characters-000000"

func hash(k string) string {
	s := sha256.Sum256([]byte(k))
	return hex.EncodeToString(s[:])
}

var now = time.Date(2026, 10, 24, 6, 23, 0, 0, time.UTC)

func newService(t *testing.T, keyHash string) (*Service, *registry.Registry) {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	s, err := New(reg, keyHash, "s1")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	return s, reg
}

func get(s *Service, path, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func feed(t *testing.T, s *Service, path string) Feed {
	t.Helper()
	w := get(s, path, "Bearer "+key)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d", path, w.Code)
	}
	var f Feed
	d := json.NewDecoder(w.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		t.Fatal(err)
	}
	return f
}

func hourAt(t time.Time) metrics.Hour {
	return metrics.Hour{Start: t.UnixMilli(), Ms: 3_600_000, Counters: map[string]int64{}, Gauges: map[string]metrics.GaugeHour{}, Histograms: map[string][]int64{}}
}

// The feed answers only the key; without one configured it answers no one.
func TestTheFeedAnswersOnlyTheKey(t *testing.T) {
	s, _ := newService(t, hash(key))
	for _, auth := range []string{"", "Bearer", "Bearer " + key[:31], "Bearer " + key + "x", "Basic " + key, key, "Bearer  " + key} {
		w := get(s, Path, auth)
		if w.Code != http.StatusUnauthorized || w.Body.Len() != 0 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("%q: %d %q", auth, w.Code, w.Body.String())
		}
	}
	if w := get(s, Path, "bearer "+key); w.Code != http.StatusOK {
		t.Fatalf("the key: %d", w.Code)
	}
	r := httptest.NewRequest(http.MethodPost, Path, nil)
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}

	off, _ := newService(t, "")
	if w := get(off, Path, "Bearer "+key); w.Code != http.StatusNotFound {
		t.Fatalf("no key configured: %d", w.Code)
	}
	reg, _ := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	defer reg.Close()
	for _, bad := range []string{"00", strings.Repeat("g", 64), hash(key) + "00"} {
		if _, err := New(reg, bad, "s1"); err == nil {
			t.Fatalf("a hash of %q was taken", bad)
		}
	}
}

// Two parts of an hour, a restart between them, are served as one hour:
// counters added, gauges' low, mean and high over both, latency quantiles
// from both parts' buckets.
func TestARestartInsideAnHourIsServedAsOneHour(t *testing.T) {
	s, _ := newService(t, hash(key))
	five := time.Date(2026, 10, 24, 5, 0, 0, 0, time.UTC)
	a := hourAt(five)
	a.Ms = 2_400_000
	a.Counters["tun_bytes_down"] = 1000
	a.Gauges["sockets_box"] = metrics.GaugeHour{Min: 9, Max: 10, Sum: 95, N: 10}
	b := hourAt(five)
	b.Ms, b.Starts = 1_199_600, 1
	b.Counters["tun_bytes_down"] = 500
	b.Counters["drains"] = 1
	b.Gauges["sockets_box"] = metrics.GaugeHour{Min: 0, Max: 10, Sum: 25, N: 5}
	bounds := len(metrics.LatencyBounds) + 1
	a.Histograms["handshake_seconds_box"] = make([]int64, bounds)
	b.Histograms["handshake_seconds_box"] = make([]int64, bounds)
	a.Histograms["handshake_seconds_box"][3] = 90 // 1 ms
	b.Histograms["handshake_seconds_box"][9] = 10 // 100 ms
	b.Histograms["forward_seconds_tun_up"] = make([]int64, bounds)
	b.Histograms["forward_seconds_tun_up"][bounds-1] = 1 // past 10 s
	if err := s.PutHour(a); err != nil {
		t.Fatal(err)
	}
	if err := s.PutHour(b); err != nil {
		t.Fatal(err)
	}
	f := feed(t, s, Path)
	if f.Schema != Schema || f.Shard != "s1" || f.ObservedAt != "2026-10-24T06:23:00Z" || len(f.Hours) != 1 {
		t.Fatalf("%+v", f)
	}
	h := f.Hours[0]
	if h.Hour != "2026-10-24T05:00:00Z" || h.Seconds != 3600 || h.Starts != 1 || h.Counters["tun_bytes_down"] != 1500 || h.Counters["drains"] != 1 {
		t.Fatalf("%+v", h)
	}
	if g := h.Gauges["sockets_box"]; g.Min != 0 || g.Max != 10 || g.Mean != 8 {
		t.Fatalf("gauge %+v", g)
	}
	l := h.LatencyMs["handshake_seconds_box"]
	if l.N != 100 || *l.P50 != 1 || *l.P95 != 100 || *l.P99 != 100 {
		t.Fatalf("latency %+v", l)
	}
	if l := h.LatencyMs["forward_seconds_tun_up"]; l.N != 1 || l.P50 != nil || l.P99 != nil {
		t.Fatalf("past the last bucket: %+v", l)
	}
}

// An hour is served once it can no longer grow, from since's hour on, at
// most a week of hours an answer, and never one older than 90 days.
func TestTheFeedServesSettledHoursInWeeks(t *testing.T) {
	s, reg := newService(t, hash(key))
	first := now.Add(-registry.OpsKept - 2*time.Hour).Truncate(time.Hour)
	for h := first; !h.After(now); h = h.Add(time.Hour) {
		if err := reg.OpsPut(h.UnixMilli(), first, func([]byte) ([]byte, error) { return json.Marshal(hourAt(h)) }); err != nil {
			t.Fatal(err)
		}
	}
	f := feed(t, s, Path)
	if len(f.Hours) != 48 || f.Hours[0].Hour != "2026-10-22T06:00:00Z" || f.Hours[47].Hour != "2026-10-24T05:00:00Z" {
		t.Fatalf("default: %d hours, %s to %s", len(f.Hours), f.Hours[0].Hour, f.Hours[len(f.Hours)-1].Hour)
	}
	// At 06:23 the hour that ended at 06:00 is settled; at 06:03 it is not.
	now = time.Date(2026, 10, 24, 7, 23, 0, 0, time.UTC)
	if f := feed(t, s, Path); f.Hours[len(f.Hours)-1].Hour != "2026-10-24T06:00:00Z" {
		t.Fatalf("at 07:23 the last hour is %s", f.Hours[len(f.Hours)-1].Hour)
	}
	now = time.Date(2026, 10, 24, 7, 3, 0, 0, time.UTC)
	if f := feed(t, s, Path); f.Hours[len(f.Hours)-1].Hour != "2026-10-24T05:00:00Z" {
		t.Fatalf("at 07:03 the last hour is %s", f.Hours[len(f.Hours)-1].Hour)
	}
	now = time.Date(2026, 10, 24, 6, 23, 0, 0, time.UTC)
	f = feed(t, s, Path+"?since=2020-01-01T00:00:00Z")
	if len(f.Hours) != MaxHours || f.Hours[0].Hour != now.Add(-registry.OpsKept).Truncate(time.Hour).Format(time.RFC3339) {
		t.Fatalf("since long ago: %d hours from %s", len(f.Hours), f.Hours[0].Hour)
	}
	if f := feed(t, s, Path+"?since=2026-10-24T03:30:00Z"); len(f.Hours) != 3 || f.Hours[0].Hour != "2026-10-24T03:00:00Z" {
		t.Fatalf("since 03:30: %+v", f.Hours)
	}
	if w := get(s, Path+"?since=yesterday", "Bearer "+key); w.Code != http.StatusBadRequest {
		t.Fatalf("a bad since: %d", w.Code)
	}
}

// Hours older than 90 days go, at upkeep and at each write.
func TestHoursGoAfterNinetyDays(t *testing.T) {
	s, reg := newService(t, hash(key))
	old := now.Add(-registry.OpsKept - time.Hour).Truncate(time.Hour)
	keep := now.Add(-registry.OpsKept + time.Hour).Truncate(time.Hour)
	for _, h := range []time.Time{old, keep} {
		if err := reg.OpsPut(h.UnixMilli(), old, func([]byte) ([]byte, error) { return json.Marshal(hourAt(h)) }); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		rows, err := reg.OpsHours(0, now.UnixMilli(), 1000)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if count() != 2 {
		t.Fatal("both hours should be there before upkeep")
	}
	if err := s.Prune(now); err != nil || count() != 1 {
		t.Fatalf("after upkeep: %d %v", count(), err)
	}
	if err := reg.OpsPut(old.UnixMilli(), old, func([]byte) ([]byte, error) { return json.Marshal(hourAt(old)) }); err != nil {
		t.Fatal(err)
	}
	if err := s.PutHour(hourAt(now.Truncate(time.Hour))); err != nil || count() != 2 {
		t.Fatalf("a write should drop the old hour: %d %v", count(), err)
	}
}

// The fleet's and the energy reports' days come exactly as the cloud holds
// them, below the public group size of five too, once closed: a fleet day at
// its end, an energy date once no report may name it.
func TestTheDaysAreExactOnceClosed(t *testing.T) {
	s, reg := newService(t, hash(key))
	s.now = time.Now
	fl, err := fleet.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	raw := `{"schema":"ftw.fleet/1","ftw_version":"v0.155.1-beta.1","channel":"beta","drivers":["sungrow"],"battery_kwh":"5-15","price_zone":"SE3","install_age":"1-6m"}`
	report, err := fleetwire.Decode([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	for range 2 {
		if ok, err := reg.FleetPut(report, yesterday); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	w := httptest.NewRecorder()
	fl.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/fleet", strings.NewReader(raw)))
	if w.Code != http.StatusNoContent {
		t.Fatalf("report: %d", w.Code)
	}
	closed := time.Now().UTC().AddDate(0, 0, -energywire.AcceptDays-1).Format(time.DateOnly)
	open := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	for _, r := range []energywire.Report{
		{Schema: energywire.Schema, Date: closed, PVGeneration: 12, GridImport: 30, GridExport: 4, BatteryCharge: 9, BatteryDischarge: 8},
		{Schema: energywire.Schema, Date: closed, PVGeneration: 3, GridImport: 10, VehicleCharge: 7},
		{Schema: energywire.Schema, Date: open, PVGeneration: 1},
	} {
		if ok, err := reg.EnergyAdd(r); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}

	f := feed(t, s, Path)
	if len(f.FleetDays) != 1 || f.FleetDays[0].Date != yesterday.Format(time.DateOnly) || f.FleetDays[0].Reports != 2 ||
		f.FleetDays[0].Drivers["sungrow"] != 2 || f.FleetDays[0].Zones["SE3"] != 2 {
		t.Fatalf("fleet days %+v", f.FleetDays)
	}
	if len(f.EnergyDays) != 1 {
		t.Fatalf("energy days %+v", f.EnergyDays)
	}
	want := map[string]any{"date": closed, "reports": 2.0, "pv_generation_kwh": 15.0, "grid_import_kwh": 40.0, "grid_export_kwh": 4.0,
		"battery_charge_kwh": 9.0, "battery_discharge_kwh": 8.0, "vehicle_charge_kwh": 7.0}
	if !maps.Equal(f.EnergyDays[0], want) {
		t.Fatalf("energy day %v", f.EnergyDays[0])
	}
	var public struct {
		Days []map[string]any `json:"days"`
	}
	w = httptest.NewRecorder()
	fl.Public(w, httptest.NewRequest(http.MethodGet, "/v1/fleet/public", nil))
	_ = json.Unmarshal(w.Body.Bytes(), &public)
	for _, d := range public.Days {
		if d["reports"] != nil {
			t.Fatalf("the public view should hide days below five: %s", w.Body.String())
		}
	}
}

// The feed's top level and each hour hold exactly these fields; a new one
// is a change to review, here and in the Worker's parser.
func TestTheFeedHoldsOnlyItsFields(t *testing.T) {
	s, _ := newService(t, hash(key))
	h := hourAt(time.Date(2026, 10, 24, 5, 0, 0, 0, time.UTC))
	h.Counters["drops_x"] = 1
	if err := s.PutHour(h); err != nil {
		t.Fatal(err)
	}
	var top map[string]json.RawMessage
	_ = json.Unmarshal(get(s, Path, "Bearer "+key).Body.Bytes(), &top)
	if got := keys(top); !slices.Equal(got, []string{"energy_days", "fleet_days", "hours", "meaning", "observed_at", "schema", "shard"}) {
		t.Fatalf("top level %v", got)
	}
	var hours []map[string]json.RawMessage
	_ = json.Unmarshal(top["hours"], &hours)
	if got := keys(hours[0]); !slices.Equal(got, []string{"counters", "gauges", "hour", "latency_ms", "seconds", "starts"}) {
		t.Fatalf("hour %v", got)
	}
	if err := s.reg.EnergyInit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reg.EnergyAdd(energywire.Report{Schema: energywire.Schema, Date: "2026-10-20", GridImport: 1}); err != nil {
		t.Fatal(err)
	}
	var energy struct {
		Days []map[string]json.RawMessage `json:"energy_days"`
	}
	_ = json.Unmarshal(get(s, Path, "Bearer "+key).Body.Bytes(), &energy)
	if len(energy.Days) != 1 || !slices.Equal(keys(energy.Days[0]), slices.Sorted(slices.Values(append([]string{"date", "reports"}, energywire.Fields...)))) {
		t.Fatalf("energy day %v", energy.Days)
	}
	var day map[string]json.RawMessage
	b, _ := json.Marshal(fleetwire.NewDay("2026-10-24"))
	_ = json.Unmarshal(b, &day)
	if got := keys(day); !slices.Equal(got, []string{"battery_kwh", "channels", "date", "drivers", "ftw_versions", "install_age", "price_zones", "reports"}) {
		t.Fatalf("fleet day %v", got)
	}
}

func keys(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
