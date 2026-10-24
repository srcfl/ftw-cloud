package fleet

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	report := fleetwire.Report{Schema: fleetwire.SchemaV1, Version: "v0.147.0", Channel: "stable", Drivers: []string{}, Battery: "none", Zone: "SE4", Age: "unknown"}
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

// A report that says how the box ran is taken beside the older shape. Its
// health counts stay out of the public view, which lists its fields by name.
func TestHealthIsCountedButNotPublished(t *testing.T) {
	reg, err := registry.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	svc, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"schema":"ftw.fleet/1","ftw_version":"v0.147.0","channel":"stable","drivers":[],"battery_kwh":"none","price_zone":"SE4","install_age":"unknown"}`,
		`{"schema":"ftw.fleet/2","ftw_version":"v0.147.0","channel":"stable","drivers":[],"battery_kwh":"none","price_zone":"SE4","install_age":"unknown","plan_solve":"5s+","plan_fallbacks":"1-3","driver_errors":"0","update":"failed"}`,
	} {
		w := httptest.NewRecorder()
		svc.ServeHTTP(w, httptest.NewRequest("POST", "/v1/fleet", strings.NewReader(body)))
		if w.Code != 204 {
			t.Fatalf("%d for %s", w.Code, body)
		}
	}
	view, err := reg.FleetView(time.Now())
	if err != nil || len(view.Days) != 1 {
		t.Fatal(view, err)
	}
	d := view.Days[0]
	if d.Reports != 2 || d.Solve["5s+"] != 1 || d.Fallbacks["1-3"] != 1 || d.Errors["0"] != 1 || d.Update["failed"] != 1 || len(d.Update) != 1 {
		t.Fatalf("%+v", d)
	}
	w := httptest.NewRecorder()
	svc.Public(w, httptest.NewRequest("GET", "/v1/fleet/public", nil))
	for _, key := range []string{"plan_solve", "plan_fallbacks", "driver_errors", `"update"`} {
		if strings.Contains(w.Body.String(), key) {
			t.Fatalf("the public view carries %s: %s", key, w.Body.String())
		}
	}
}
