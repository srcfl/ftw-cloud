package gateway

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
	"github.com/srcfl/ftw/go/protocol/ohttp"
	"github.com/srcfl/ftw/go/protocol/reportwire"
)

var now = time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)

const good = `{"schema":"ftw.energy/1","date":"2026-10-23","pv_generation_kwh":12,"grid_import_kwh":30,"grid_export_kwh":4,"battery_charge_kwh":9,"battery_discharge_kwh":8,"vehicle_charge_kwh":0}`

func newService(t *testing.T) (*Service, *registry.Registry, ohttp.KeyConfig) {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	k, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := ohttp.NewGateway(ohttp.Key{ID: 9, Private: k})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(reg, gw)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }
	return s, reg, gw.Configs()[0]
}

func inner(content string) ohttp.Request {
	return ohttp.Request{Method: reportwire.Method, Scheme: reportwire.Scheme, Authority: reportwire.Authority, Path: reportwire.Path, Content: []byte(content)}
}

const fleet = `{"schema":"ftw.fleet/1","ftw_version":"v0.146.0-beta.1","channel":"beta","drivers":["pixii","pixii_pv"],"battery_kwh":"5-15","price_zone":"SE4","install_age":"1-6m"}`

func post(s *Service, body []byte, contentType string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/ohttp", bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	r.RemoteAddr = "198.51.100.8:443"
	s.ServeHTTP(w, r)
	return w
}

// send seals msg as a box would and returns the gateway's inner status.
func send(t *testing.T, s *Service, cfg ohttp.KeyConfig, msg []byte) int {
	t.Helper()
	sealed, reader, err := ohttp.Encapsulate(cfg, msg)
	if err != nil {
		t.Fatal(err)
	}
	w := post(s, sealed, ohttp.RequestType)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != ohttp.ResponseType || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("outer %d %v", w.Code, w.Header())
	}
	plain, err := reader.Open(w.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ohttp.ParseResponse(plain)
	if err != nil || len(plain) != reportwire.ResponseSize {
		t.Fatalf("inner %x %v", plain, err)
	}
	return resp.Status
}

func TestAReportAddsToItsDate(t *testing.T) {
	s, reg, cfg := newService(t)
	for range 2 {
		if got := send(t, s, cfg, inner(good).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
			t.Fatalf("status %d", got)
		}
	}
	totals, err := reg.EnergyTotals("2026-10-23", "2026-10-23")
	if d := totals["2026-10-23"]; err != nil || d.Reports != 2 || d.Sums != [6]int64{24, 60, 8, 18, 16, 0} {
		t.Fatalf("%+v %v", d, err)
	}
}

// A fleet report through the gateway lands in the fleet's day totals, the
// ones /v1/fleet/public reads, and nothing of it in the energy totals.
func TestAFleetReportAddsToTheFleetTotals(t *testing.T) {
	s, reg, cfg := newService(t)
	if got := send(t, s, cfg, inner(fleet).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("status %d", got)
	}
	view, err := reg.FleetView(now)
	if err != nil || len(view.Days) != 1 || view.Days[0].Reports != 1 || view.Days[0].Zones["SE4"] != 1 {
		t.Fatalf("fleet %+v %v", view, err)
	}
	if totals, _ := reg.EnergyTotals("2026-01-01", "2026-12-31"); len(totals) != 0 {
		t.Fatalf("a fleet report reached the energy totals: %v", totals)
	}
	var r fleetwire.Report
	_ = json.Unmarshal([]byte(fleet), &r)
	if r.Schema != fleetwire.Schema {
		t.Fatal("fixture")
	}
}

// Anything but the one padded request with one valid report gets a sealed
// 400 and adds nothing.
func TestJunkIsRefusedAndAddsNothing(t *testing.T) {
	s, reg, cfg := newService(t)
	pad := reportwire.RequestSize
	other := func(f func(*ohttp.Request)) []byte {
		r := inner(good)
		f(&r)
		return r.Marshal(pad)
	}
	for name, msg := range map[string][]byte{
		"another path":            other(func(r *ohttp.Request) { r.Path = "/v1/fleet" }),
		"another method":          other(func(r *ohttp.Request) { r.Method = "PUT" }),
		"another host":            other(func(r *ohttp.Request) { r.Authority = "example.com" }),
		"plain http":              other(func(r *ohttp.Request) { r.Scheme = "http" }),
		"a header":                other(func(r *ohttp.Request) { r.Fields = []ohttp.Field{{Name: "x-home", Value: "1"}} }),
		"not padded":              inner(good).Marshal(0),
		"padded more":             inner(good).Marshal(pad + 1),
		"extra field":             inner(strings.TrimSuffix(good, "}") + `,"home":"a"}`).Marshal(pad),
		"too much solar":          inner(strings.Replace(good, `"pv_generation_kwh":12`, `"pv_generation_kwh":1001`, 1)).Marshal(pad),
		"negative":                inner(strings.Replace(good, `:12,`, `:-12,`, 1)).Marshal(pad),
		"today":                   inner(strings.Replace(good, "2026-10-23", "2026-10-24", 1)).Marshal(pad),
		"four days back":          inner(strings.Replace(good, "2026-10-23", "2026-10-20", 1)).Marshal(pad),
		"other schema":            inner(strings.Replace(good, "ftw.energy/1", "ftw.energy/2", 1)).Marshal(pad),
		"no schema":               inner(`{"date":"2026-10-23"}`).Marshal(pad),
		"energy and fleet in one": inner(strings.TrimSuffix(fleet, "}") + `,"pv_generation_kwh":12}`).Marshal(pad),
		"bad fleet":               inner(strings.Replace(fleet, `"SE4"`, `"myhouse"`, 1)).Marshal(pad),
		"a response":              ohttp.Response{Status: 200, Content: []byte(good)}.Marshal(pad),
		"empty":                   nil,
	} {
		if got := send(t, s, cfg, msg); got != http.StatusBadRequest {
			t.Fatalf("%s: %d", name, got)
		}
	}
	sealed, _, _ := ohttp.Encapsulate(cfg, inner(good).Marshal(pad))
	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	for name, c := range map[string]struct {
		body  []byte
		ctype string
		code  int
	}{
		"tampered":     {tampered, ohttp.RequestType, http.StatusBadRequest},
		"random bytes": {bytes.Repeat([]byte{9}, 400), ohttp.RequestType, http.StatusBadRequest},
		"plain JSON":   {[]byte(good), "application/json", http.StatusUnsupportedMediaType},
		"oversized":    {make([]byte, maxRequest+1), ohttp.RequestType, http.StatusRequestEntityTooLarge},
	} {
		w := post(s, c.body, c.ctype)
		if w.Code != c.code || w.Header().Get("Content-Type") == ohttp.ResponseType {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/ohttp", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET %d", w.Code)
	}
	if totals, _ := reg.EnergyTotals("2026-01-01", "2026-12-31"); len(totals) != 0 {
		t.Fatalf("junk reached the totals: %v", totals)
	}
	if view, _ := reg.FleetView(now); len(view.Days) != 0 {
		t.Fatalf("junk reached the fleet totals: %+v", view)
	}
}

// One budget for all requests, since they all come from the relay.
func TestRequestsShareOneBudget(t *testing.T) {
	s, _, cfg := newService(t)
	sealed, _, _ := ohttp.Encapsulate(cfg, inner(good).Marshal(reportwire.RequestSize))
	for i := range int(burst) {
		if w := post(s, sealed, ohttp.RequestType); w.Code == http.StatusTooManyRequests {
			t.Fatalf("limited after %d", i)
		}
	}
	if w := post(s, sealed, ohttp.RequestType); w.Code != http.StatusTooManyRequests {
		t.Fatalf("over budget: %d", w.Code)
	}
	now = now.Add(time.Second)
	defer func() { now = now.Add(-time.Second) }()
	if w := post(s, sealed, ohttp.RequestType); w.Code != http.StatusOK {
		t.Fatalf("after a second: %d", w.Code)
	}
}

type publicView struct {
	Schema     string           `json:"schema"`
	Meaning    string           `json:"meaning"`
	ObservedAt string           `json:"observed_at"`
	Minimum    int              `json:"minimum"`
	Days       []map[string]any `json:"days"`
}

// A date is public once it is closed for reports and holds at least five.
func TestAPublicDateIsClosedAndHoldsFiveReports(t *testing.T) {
	s, reg, _ := newService(t)
	add := func(date string, n int) {
		var r energywire.Report
		_ = json.Unmarshal([]byte(strings.Replace(good, "2026-10-23", date, 1)), &r)
		for range n {
			if ok, err := reg.EnergyAdd(r); err != nil || !ok {
				t.Fatal(err)
			}
		}
	}
	add("2026-10-18", 5)
	add("2026-10-19", 4)
	// Five reports, one of them with a car: that sum is that car's.
	add("2026-10-17", 4)
	var car energywire.Report
	_ = json.Unmarshal([]byte(strings.Replace(strings.Replace(good, "2026-10-23", "2026-10-17", 1), `"vehicle_charge_kwh":0`, `"vehicle_charge_kwh":20`, 1)), &car)
	if ok, err := reg.EnergyAdd(car); err != nil || !ok {
		t.Fatal(err)
	}
	add("2026-10-23", 9) // still open for reports
	add("2026-09-23", 9) // past the window

	w := httptest.NewRecorder()
	s.Public(w, httptest.NewRequest(http.MethodGet, "/v1/energy/public", nil))
	var v publicView
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if v.Schema != "ftw.energy-public/1" || v.Meaning != "daily reports, not homes" || v.Minimum != 5 || v.ObservedAt != "2026-10-24T09:00:00Z" {
		t.Fatalf("view %+v", v)
	}
	if len(v.Days) != 27 || v.Days[0]["date"] != "2026-10-20" || v.Days[26]["date"] != "2026-09-24" {
		t.Fatalf("%d days from %v to %v", len(v.Days), v.Days[0]["date"], v.Days[len(v.Days)-1]["date"])
	}
	byDate := map[string]map[string]any{}
	for _, d := range v.Days {
		if len(d) != 2+len(energywire.Fields) {
			t.Fatalf("fields %v", d)
		}
		byDate[d["date"].(string)] = d
	}
	if d := byDate["2026-10-18"]; d["reports"] != 5.0 || d["pv_generation_kwh"] != 60.0 || d["vehicle_charge_kwh"] != 0.0 {
		t.Fatalf("five reports: %v", d)
	}
	if d := byDate["2026-10-17"]; d["reports"] != 5.0 || d["pv_generation_kwh"] != 60.0 || d["vehicle_charge_kwh"] != nil {
		t.Fatalf("one car among five: %v", d)
	}
	for _, date := range []string{"2026-10-19", "2026-10-20"} {
		for k, v := range byDate[date] {
			if k != "date" && v != nil {
				t.Fatalf("%s shows %s=%v", date, k, v)
			}
		}
	}
	if _, open := byDate["2026-10-23"]; open {
		t.Fatal("a date still open for reports is public")
	}
}

func TestTheKeyConfigurationIsServed(t *testing.T) {
	s, _, cfg := newService(t)
	w := httptest.NewRecorder()
	s.Keys(w, httptest.NewRequest(http.MethodGet, "/.well-known/ohttp-gateway", nil))
	if w.Header().Get("Content-Type") != ohttp.KeysType || !bytes.Equal(w.Body.Bytes(), ohttp.MarshalKeys(cfg)) {
		t.Fatalf("%v %x", w.Header(), w.Body.Bytes())
	}
	off, err := New(s.reg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []http.HandlerFunc{off.ServeHTTP, off.Keys} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/v1/ohttp", nil))
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("without a key: %d", w.Code)
		}
	}
}
