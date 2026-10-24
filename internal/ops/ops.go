// Package ops is Sourceful's internal view of the service, for running it and
// for understanding the fleet. It keeps the service's own hours (package
// metrics) for 90 days, and serves them with the exact daily totals of the
// anonymous fleet and energy reports on GET /v1/ops to one key: the one the
// project stats Worker holds.
//
// Nothing in it names a home, a device or an address. Every hour sums over
// the whole process, as every series does. The days are the totals that
// /v1/fleet/public and /v1/energy/public hold to a group size, which keep no
// report; here they come exact, but only once closed, so that two answers
// never differ by one report.
package ops

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

// Path is where the feed answers.
const Path = "/v1/ops"

const (
	Schema  = "ftw.cloud-ops/1"
	Meaning = "sums over the whole service, and closed daily totals over all reports; no home, device or address"
	// MaxHours is the most hours one answer carries: a week.
	MaxHours = 168
	// settle is how long after its end an hour may still grow: the next
	// process adds the rest of an hour a restart split at its first sample.
	settle = 5 * time.Minute
	// defaultBack is how far back an answer starts without since.
	defaultBack = 48 * time.Hour
)

// Service keeps the hours and serves the feed.
type Service struct {
	reg   *registry.Registry
	key   []byte // SHA-256 of the key; nil serves no one
	shard string
	now   func() time.Time
}

// New keeps hours in reg. Until UseKey takes a key, the feed serves no one,
// and the hours are kept all the same.
func New(reg *registry.Registry, shard string) (*Service, error) {
	if err := reg.OpsInit(); err != nil {
		return nil, err
	}
	if err := reg.FleetInit(); err != nil {
		return nil, err
	}
	if err := reg.EnergyInit(); err != nil {
		return nil, err
	}
	if err := reg.OpsPrune(time.Now()); err != nil {
		return nil, err
	}
	return &Service{reg: reg, shard: shard, now: time.Now}, nil
}

// UseKey makes the feed answer the key whose SHA-256 is keySHA256, in hex,
// which is no secret: it does not help anyone make the key. Spaces, line
// ends and quotes around it, as an env file may leave them, are dropped.
// Empty turns the feed off. A hash that is not 64 hex digits turns it off
// too and is an error to log: a typo in an internal setting must not stop
// the service.
func (s *Service) UseKey(keySHA256 string) error {
	s.key = nil
	h := strings.Trim(keySHA256, " \t\r\n\"'")
	if h == "" {
		return nil
	}
	key, err := hex.DecodeString(h)
	if err != nil || len(key) != sha256.Size {
		return errors.New("ops: the key's hash is not 64 hex digits")
	}
	s.key = key
	return nil
}

// PutHour adds h to the hour kept for its start.
func (s *Service) PutHour(h metrics.Hour) error {
	return s.reg.OpsPut(h.Start, s.now(), func(old []byte) ([]byte, error) {
		if old == nil {
			return json.Marshal(h)
		}
		var kept metrics.Hour
		if err := json.Unmarshal(old, &kept); err != nil {
			return nil, err
		}
		kept.Merge(h)
		return json.Marshal(kept)
	})
}

// Prune drops hours past registry.OpsKept.
func (s *Service) Prune(now time.Time) error { return s.reg.OpsPrune(now) }

// allowed reports whether r carries the key.
func (s *Service) allowed(r *http.Request) bool {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || len(token) < 32 {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(sum[:], s.key) == 1
}

// Feed is the whole answer.
type Feed struct {
	Schema     string          `json:"schema"`
	Meaning    string          `json:"meaning"`
	Shard      string          `json:"shard"`
	ObservedAt string          `json:"observed_at"`
	Hours      []HourView      `json:"hours"`
	FleetDays  []fleetwire.Day `json:"fleet_days"`
	// EnergyDays are the closed dates' energy totals, newest first: the
	// date, reports and each of energywire.Fields.
	EnergyDays []map[string]any `json:"energy_days"`
}

// HourView is one settled hour as the feed carries it.
type HourView struct {
	Hour      string                 `json:"hour"`
	Seconds   int64                  `json:"seconds"`
	Starts    int64                  `json:"starts"`
	Counters  map[string]int64       `json:"counters"`
	Gauges    map[string]GaugeView   `json:"gauges"`
	LatencyMs map[string]LatencyView `json:"latency_ms"`
}

// GaugeView is a gauge's low, mean and high over the hour's samples.
type GaugeView struct {
	Min  int64   `json:"min"`
	Mean float64 `json:"mean"`
	Max  int64   `json:"max"`
}

// LatencyView is how many durations an hour counted and the upper bounds of
// the buckets that hold its quantiles, in milliseconds. A quantile is null
// when there is none or it lies past the last bucket.
type LatencyView struct {
	N   int64    `json:"n"`
	P50 *float64 `json:"p50"`
	P95 *float64 `json:"p95"`
	P99 *float64 `json:"p99"`
}

func view(h metrics.Hour) HourView {
	v := HourView{Hour: time.UnixMilli(h.Start).UTC().Format(time.RFC3339), Seconds: int64(math.Round(float64(h.Ms) / 1000)),
		Starts: h.Starts, Counters: h.Counters, Gauges: map[string]GaugeView{}, LatencyMs: map[string]LatencyView{}}
	if v.Counters == nil {
		v.Counters = map[string]int64{}
	}
	for k, g := range h.Gauges {
		if g.N > 0 {
			v.Gauges[k] = GaugeView{Min: g.Min, Mean: math.Round(float64(g.Sum)/float64(g.N)*1000) / 1000, Max: g.Max}
		}
	}
	for k, b := range h.Histograms {
		var n int64
		for _, c := range b {
			n += c
		}
		l := LatencyView{N: n}
		if n > 0 {
			l.P50, l.P95, l.P99 = ms(b, 0.5), ms(b, 0.95), ms(b, 0.99)
		}
		v.LatencyMs[k] = l
	}
	return v
}

func ms(counts []int64, q float64) *float64 {
	s := metrics.Quantile(counts, q)
	if math.IsInf(s, 0) {
		return nil
	}
	v := math.Round(s*1e6) / 1e3
	return &v
}

// ServeHTTP answers GET /v1/ops?since=<RFC 3339> to the key, with the settled
// hours from since's hour on, at most MaxHours, and the fleet's days.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.key == nil {
		http.NotFound(w, r)
		return
	}
	if !s.allowed(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ftw-cloud-ops"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	now := s.now()
	from := now.Add(-defaultBack)
	if q := r.URL.Query().Get("since"); q != "" {
		t, err := time.Parse(time.RFC3339, q)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		from = t
	}
	from = maxTime(from, now.Add(-registry.OpsKept)).UTC().Truncate(time.Hour)
	// An hour is served once it can no longer grow.
	until := now.Add(-settle).UTC().Truncate(time.Hour).Add(-time.Hour)
	rows, err := s.reg.OpsHours(from.UnixMilli(), until.Add(time.Hour).UnixMilli(), MaxHours)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	fleet, err := s.reg.FleetView(now)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	energy, err := s.energyDays(now)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	feed := Feed{Schema: Schema, Meaning: Meaning, Shard: s.shard, ObservedAt: now.UTC().Format(time.RFC3339), Hours: []HourView{}, FleetDays: []fleetwire.Day{}, EnergyDays: energy}
	// A fleet day closes at its end: until then each report adds to it.
	today := now.UTC().Format(time.DateOnly)
	for _, d := range fleet.Days {
		if d.Date < today {
			feed.FleetDays = append(feed.FleetDays, d)
		}
	}
	for _, raw := range rows {
		var h metrics.Hour
		if err := json.Unmarshal(raw, &h); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		feed.Hours = append(feed.Hours, view(h))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(feed)
}

// energyDays are the closed dates of the energy reports, as
// /v1/energy/public names them, without its group size.
func (s *Service) energyDays(now time.Time) ([]map[string]any, error) {
	today := now.UTC().Truncate(24 * time.Hour)
	first, last := today.AddDate(0, 0, -registry.EnergyDays), today.AddDate(0, 0, -energywire.AcceptDays-1)
	totals, err := s.reg.EnergyTotals(first.Format(time.DateOnly), last.Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	days := []map[string]any{}
	for d := last; !d.Before(first); d = d.AddDate(0, 0, -1) {
		day, ok := totals[d.Format(time.DateOnly)]
		if !ok || day.Reports == 0 {
			continue
		}
		row := map[string]any{"date": day.Date, "reports": day.Reports}
		for i, name := range energywire.Fields {
			row[name] = day.Sums[i]
		}
		days = append(days, row)
	}
	return days, nil
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
