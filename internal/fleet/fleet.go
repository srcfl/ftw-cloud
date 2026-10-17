// Package fleet reduces anonymous box reports to bounded daily counts.
package fleet

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

type Service struct {
	reg    *registry.Registry
	now    func() time.Time
	mu     sync.Mutex
	at     time.Time
	tokens float64
}

func New(reg *registry.Registry) (*Service, error) {
	if err := reg.FleetInit(); err != nil {
		return nil, err
	}
	if err := reg.FleetPrune(time.Now()); err != nil {
		return nil, err
	}
	return &Service{reg: reg, now: time.Now, tokens: 120}, nil
}

// ServeHTTP accepts reports only. Public requests never read totals.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.allow() {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fleetwire.MaxBodyBytes))
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	report, err := fleetwire.Decode(data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ok, err := s.reg.FleetPut(report, s.now())
	switch {
	case err != nil:
		w.WriteHeader(http.StatusServiceUnavailable)
	case !ok:
		w.WriteHeader(http.StatusTooManyRequests)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// Stats belongs only on the operator's loopback listener.
func (s *Service) Stats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	view, err := s.reg.FleetView(s.now())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// One shared budget stores no addresses and admits five reports a second.
func (s *Service) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.at.IsZero() {
		s.tokens = min(120, s.tokens+max(0, now.Sub(s.at).Seconds())*5)
	}
	s.at = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

func (s *Service) Prune(now time.Time) error { return s.reg.FleetPrune(now) }
