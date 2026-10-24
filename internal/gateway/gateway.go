// Package gateway is the Oblivious HTTP gateway (RFC 9458) for the box's two
// anonymous daily reports, and the public view of the energy totals.
//
// A box seals each report alone to the gateway key and posts it to an
// independent relay, which forwards it here. The gateway sees the report and
// the relay's address, never the box's. It reads the report's schema, adds a
// fleet report to the fleet's day totals and an energy report to the
// energy's, and keeps nothing else: no row, logged body or address per
// report.
//
// A report cannot prove that a real box sent it. Bounds per field and a cap
// per date keep junk to noise. Privacy Pass-style tokens would be the fix.
package gateway

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
	"github.com/srcfl/ftw/go/protocol/ohttp"
	"github.com/srcfl/ftw/go/protocol/reportwire"
)

const (
	// maxRequest is a sealed request, 1,591 bytes (header, key, padded
	// message and tag), with room to spare.
	maxRequest = 2 << 10
	// Minimum is the group size for a public date, as /v1/fleet/public's.
	Minimum = 5
	// rate and burst are each report kind's budget, spent only by a report
	// that opened and decoded, so junk cannot use up the real reports'.
	// Every request arrives from the relay, so there is no address worth
	// keeping apart.
	rate  = 5.0
	burst = 120.0
)

// bodyDeadline bounds reading a request body, so a slow sender cannot hold a
// connection open.
var bodyDeadline = 10 * time.Second

type Service struct {
	reg *registry.Registry
	// gw is nil on a host without a gateway key; the gateway routes then say
	// so and the public view still answers.
	gw   *ohttp.Gateway
	keys []byte
	now  func() time.Time

	fleet, energy budget
}

// budget is a token bucket.
type budget struct {
	mu     sync.Mutex
	at     time.Time
	tokens float64
}

func New(reg *registry.Registry, gw *ohttp.Gateway) (*Service, error) {
	if err := reg.FleetInit(); err != nil {
		return nil, err
	}
	if err := reg.EnergyInit(); err != nil {
		return nil, err
	}
	if err := reg.ReportsInit(); err != nil {
		return nil, err
	}
	s := &Service{reg: reg, gw: gw, now: time.Now}
	s.fleet.tokens, s.energy.tokens = burst, burst
	if err := s.Prune(time.Now()); err != nil {
		return nil, err
	}
	if gw != nil {
		s.keys = ohttp.MarshalKeys(gw.Configs()...)
	}
	return s, nil
}

// ServeHTTP is the gateway, POST /v1/ohttp. A request it cannot open gets a
// plain 400. One it opens gets a sealed answer: 204 when the report is
// added or was counted already, 400 when it is not one valid report, 429
// when its kind's budget or its day is full.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.gw == nil {
		http.Error(w, "not available yet", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); media != ohttp.RequestType {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyDeadline))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		// The rest of the body is never read: close rather than wait for it.
		w.Header().Set("Connection", "close")
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusRequestTimeout)
		}
		return
	}
	_ = rc.SetReadDeadline(time.Time{})
	msg, sealer, err := s.gw.Decapsulate(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	answer, err := sealer.Seal(reportwire.Response(s.add(msg)))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ohttp.ResponseType)
	_, _ = w.Write(answer)
}

// add reads the one request the gateway answers and adds its report to the
// day totals of its kind, once: a report whose id was counted already is
// answered 204, adds nothing and spends no budget, so a replay or a retry is
// harmless and cannot crowd out real reports.
func (s *Service) add(msg []byte) int {
	now := s.now()
	report, ok := reportwire.Read(msg)
	if !ok || !reportwire.Fresh(report.Day, now) {
		return http.StatusBadRequest
	}
	switch seen, err := s.reg.ReportSeen(report.Day, report.ID); {
	case err != nil:
		return http.StatusServiceUnavailable
	case seen:
		return http.StatusNoContent
	}
	var added, repeat bool
	var err error
	switch reportwire.Schema(report.Body) {
	case fleetwire.Schema, fleetwire.SchemaV1:
		fleet, decodeErr := fleetwire.Decode(report.Body)
		if decodeErr != nil {
			return http.StatusBadRequest
		}
		if !s.fleet.allow(now) {
			return http.StatusTooManyRequests
		}
		added, repeat, err = s.reg.FleetPutOnce(report.Day, report.ID, fleet, now)
	case energywire.Schema:
		energy, decodeErr := energywire.Decode(report.Body, now)
		if decodeErr != nil {
			return http.StatusBadRequest
		}
		if !s.energy.allow(now) {
			return http.StatusTooManyRequests
		}
		added, repeat, err = s.reg.EnergyAddOnce(report.Day, report.ID, energy)
	default:
		return http.StatusBadRequest
	}
	switch {
	case err != nil:
		return http.StatusServiceUnavailable
	case repeat:
		return http.StatusNoContent
	case !added:
		return http.StatusTooManyRequests
	}
	return http.StatusNoContent
}

// Keys serves the gateway's key configuration at
// /.well-known/ohttp-gateway (RFC 9540). Boxes do not read it: a release pins
// the key. It is here for the relay's operator and for anyone checking the
// pin.
func (s *Service) Keys(w http.ResponseWriter, r *http.Request) {
	if s.gw == nil {
		http.Error(w, "not available yet", http.StatusNotImplemented)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", ohttp.KeysType)
	_, _ = w.Write(s.keys)
}

// Public is GET /v1/energy/public: the closed dates of the last EnergyDays,
// newest first. A date shows only once no report may name it any more, so
// two readings never differ by one report. A date with fewer than Minimum
// reports shows null, and so does a sum that between one and Minimum-1 of
// them had any of: five reports with one car is that car's charge. A sum
// nobody had any of shows 0.
func (s *Service) Public(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=60")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	now := s.now().UTC()
	today := now.Truncate(24 * time.Hour)
	first, last := today.AddDate(0, 0, -registry.EnergyDays), today.AddDate(0, 0, -energywire.AcceptDays-1)
	totals, err := s.reg.EnergyTotals(first.Format(time.DateOnly), last.Format(time.DateOnly))
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	days := []map[string]any{}
	for d := last; !d.Before(first); d = d.AddDate(0, 0, -1) {
		date := d.Format(time.DateOnly)
		day, row := totals[date], map[string]any{"date": date, "reports": nil}
		for i, name := range energywire.Fields {
			row[name] = nil
			if day.Reports >= Minimum && (day.Had[i] == 0 || day.Had[i] >= Minimum) {
				row[name] = day.Sums[i]
			}
		}
		if day.Reports >= Minimum {
			row["reports"] = day.Reports
		}
		days = append(days, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema": "ftw.energy-public/1", "meaning": "daily reports, not homes",
		"observed_at": now.Format(time.RFC3339), "minimum": Minimum, "days": days})
}

// Prune drops energy totals and report ids past their days.
func (s *Service) Prune(now time.Time) error {
	if err := s.reg.EnergyPrune(now); err != nil {
		return err
	}
	return s.reg.ReportsPrune(now)
}

func (b *budget) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.at.IsZero() {
		b.tokens = min(burst, b.tokens+max(0, now.Sub(b.at).Seconds())*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
