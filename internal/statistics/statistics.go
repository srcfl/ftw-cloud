// Package statistics publishes only cells that meet the consent's group rules.
package statistics

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
)

type Service struct {
	Reg     *registry.Registry
	Enabled bool
	mu      sync.Mutex
	cached  []byte
	at      time.Time
}

func New(reg *registry.Registry) (*Service, error) {
	if err := reg.StatisticsInit(); err != nil {
		return nil, err
	}
	return &Service{Reg: reg}, nil
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=60")
	if !s.Enabled {
		w.Header().Set("Retry-After", "3600")
		w.Header().Set("FTW-Statistics-State", "disabled")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil || time.Since(s.at) > time.Minute {
		view, err := s.Reg.StatisticsView(time.Now())
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		data, err := json.Marshal(view)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		s.cached, s.at = data, time.Now()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(s.cached)
}

func (s *Service) Prune(now time.Time) error { return s.Reg.StatisticsPrune(now) }
