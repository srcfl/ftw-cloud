package fleet

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

func TestPublicFleetHidesSmallDaysAndEachSmallLabel(t *testing.T) {
	reg, err := registry.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	svc, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	svc.now = func() time.Time { return now }
	report := fleetwire.Report{Schema: fleetwire.Schema, Version: "v0.147.0", Channel: "stable", Drivers: []string{}, Battery: "none", Zone: "SE4", Age: "unknown"}
	for range 4 {
		_, err = reg.FleetPut(report, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	get := func() map[string]any {
		w := httptest.NewRecorder()
		svc.Public(w, httptest.NewRequest("GET", "/v1/fleet/public", nil))
		var v map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	// Today is still open, so its running counts are not listed: whoever
	// forwarded a report could see which count it moved.
	if days := get()["days"].([]any); len(days) != 0 {
		t.Fatalf("today listed: %v", days)
	}
	svc.now = func() time.Time { return now.Add(24 * time.Hour) }
	v := get()
	d := v["days"].([]any)[0].(map[string]any)
	if d["reports"] != nil || len(d["ftw_versions"].(map[string]any)) != 0 {
		t.Fatal("small day exposed")
	}
	report.Version = "v0.147.1"
	_, _ = reg.FleetPut(report, now)
	v = get()
	d = v["days"].([]any)[0].(map[string]any)
	if d["reports"] != float64(5) || len(d["ftw_versions"].(map[string]any)) != 0 {
		t.Fatal("small version exposed")
	}
	if d["channels"].(map[string]any)["stable"] != float64(5) {
		t.Fatal("safe cell hidden")
	}
}
