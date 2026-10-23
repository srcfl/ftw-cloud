package fleet

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

// Public exports only cells already large enough for the project dashboard.
// A day below the minimum has a null count and no dimension labels.
func (s *Service) Public(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=60")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	view, err := s.reg.FleetView(s.now())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// Five since 23 October 2026 (Fredrik): the fleet is small and the
	// reports carry no home id. A day and each label below it stay hidden.
	const minimum = 5
	days := make([]map[string]any, 0, len(view.Days))
	for _, d := range view.Days {
		row := map[string]any{"date": d.Date, "reports": nil}
		for key, values := range map[string]map[string]int{"ftw_versions": d.Versions, "channels": d.Channels, "drivers": d.Drivers, "battery_kwh": d.Battery, "price_zones": d.Zones, "install_age": d.Age} {
			safe := map[string]int{}
			if d.Reports >= minimum {
				for label, n := range values {
					if n >= minimum {
						safe[label] = n
					}
				}
			}
			row[key] = safe
		}
		if d.Reports >= minimum {
			row["reports"] = d.Reports
		}
		days = append(days, row)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"schema": "ftw.fleet-public/1", "meaning": fleetwire.Meaning, "observed_at": s.now().UTC().Format(time.RFC3339), "minimum": minimum, "days": days})
}
