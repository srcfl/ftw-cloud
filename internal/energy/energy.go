// Package energy is the Oblivious HTTP gateway (RFC 9458) for the anonymous
// daily energy report, and the public view of its totals.
//
// A box seals one report a day to the gateway key and posts it to an
// independent relay, which forwards it here. The gateway sees the report and
// the relay's address, never the box's. It adds the six sums to that date's
// totals and keeps nothing else: no row, logged body or address per report.
//
// A report cannot prove that a real box sent it. Bounds per field and a cap
// per date keep junk to noise. Privacy Pass-style tokens would be the fix.
package energy

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/ohttp"
)

const (
	// maxRequest is a sealed request: header, key, padded message and tag,
	// with room to spare.
	maxRequest = 1 << 10
	// Minimum is the group size for a public date, as /v1/fleet/public's.
	Minimum = 5
	// rate and burst are one shared budget for every request. All of them
	// arrive from the relay, so there is no address worth keeping apart.
	rate  = 5.0
	burst = 120.0
)

type Service struct {
	reg *registry.Registry
	// gw is nil on a host without a gateway key; the gateway routes then say
	// so and the public view still answers.
	gw   *ohttp.Gateway
	keys []byte
	now  func() time.Time

	mu     sync.Mutex
	at     time.Time
	tokens float64
}

func New(reg *registry.Registry, gw *ohttp.Gateway) (*Service, error) {
	if err := reg.EnergyInit(); err != nil {
		return nil, err
	}
	if err := reg.EnergyPrune(time.Now()); err != nil {
		return nil, err
	}
	s := &Service{reg: reg, gw: gw, now: time.Now, tokens: burst}
	if gw != nil {
		s.keys = ohttp.MarshalKeys(gw.Configs()...)
	}
	return s, nil
}

// ServeHTTP is the gateway, POST /v1/ohttp. A request it cannot open gets a
// plain 400. One it opens gets a sealed answer: 204 when the report is
// added, 400 when it is not a valid report, 429 when its date is full.
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
	if !s.allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequest))
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	msg, sealer, err := s.gw.Decapsulate(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	answer, err := sealer.Seal(ohttp.Response{Status: s.add(msg)}.Marshal(energywire.ResponseSize))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ohttp.ResponseType)
	_, _ = w.Write(answer)
}

// add reads the one request the gateway answers and adds its report.
func (s *Service) add(msg []byte) int {
	req, err := ohttp.ParseRequest(msg)
	if err != nil || len(msg) != energywire.RequestSize || req.Method != energywire.Method || req.Scheme != energywire.Scheme ||
		req.Authority != energywire.Authority || req.Path != energywire.Path || len(req.Fields) != 0 {
		return http.StatusBadRequest
	}
	report, err := energywire.Decode(req.Content, s.now())
	if err != nil {
		return http.StatusBadRequest
	}
	switch ok, err := s.reg.EnergyAdd(report); {
	case err != nil:
		return http.StatusServiceUnavailable
	case !ok:
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
// reports shows null.
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
			if day.Reports >= Minimum {
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

func (s *Service) Prune(now time.Time) error { return s.reg.EnergyPrune(now) }

func (s *Service) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.at.IsZero() {
		s.tokens = min(burst, s.tokens+max(0, now.Sub(s.at).Seconds())*rate)
	}
	s.at = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}
