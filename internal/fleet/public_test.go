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
	for range 9 {
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
	v := get()
	d := v["days"].([]any)[0].(map[string]any)
	if d["reports"] != nil || len(d["ftw_versions"].(map[string]any)) != 0 {
		t.Fatal("small day exposed")
	}
	report.Version = "v0.147.1"
	_, _ = reg.FleetPut(report, now)
	v = get()
	d = v["days"].([]any)[0].(map[string]any)
	if d["reports"] != float64(10) || len(d["ftw_versions"].(map[string]any)) != 0 {
		t.Fatal("small version exposed")
	}
	if d["channels"].(map[string]any)["stable"] != float64(10) {
		t.Fatal("safe cell hidden")
	}
}
