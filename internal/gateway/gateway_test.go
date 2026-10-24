package gateway

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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

// inner is one report as a box sends it: a fresh id, sent today.
func inner(content string) ohttp.Request {
	return innerWith(content, newID(), "2026-10-24")
}

func innerWith(content string, id []byte, day string) ohttp.Request {
	return ohttp.Request{Method: reportwire.Method, Scheme: reportwire.Scheme, Authority: reportwire.Authority, Path: reportwire.Path,
		Fields:  []ohttp.Field{{Name: "report-id", Value: base64.RawURLEncoding.EncodeToString(id)}, {Name: "report-day", Value: day}},
		Content: []byte(content)}
}

func newID() []byte {
	id := make([]byte, reportwire.IDBytes)
	_, _ = rand.Read(id)
	return id
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
	if r.Schema != fleetwire.SchemaV1 {
		t.Fatal("fixture")
	}
	// The report that says how the box ran takes the same way, and its
	// health is counted beside the shape.
	withHealth := strings.Replace(strings.TrimSuffix(fleet, "}"), `"ftw.fleet/1"`, `"ftw.fleet/2"`, 1) +
		`,"plan_solve":"1-5s","plan_fallbacks":"0","driver_errors":"0-1%","update":"failed"}`
	if got := send(t, s, cfg, inner(withHealth).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("status %d for an ftw.fleet/2 report", got)
	}
	view, err = reg.FleetView(now)
	if err != nil || view.Days[0].Reports != 2 || view.Days[0].Update["failed"] != 1 || view.Days[0].Solve["1-5s"] != 1 {
		t.Fatalf("fleet %+v %v", view, err)
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

// A replayed request, or a retry of one report, counts once and is still
// answered 204, so neither the relay nor a lost answer moves a total.
func TestAReportCountsOnceHoweverOftenItArrives(t *testing.T) {
	s, reg, cfg := newService(t)
	sealed, _, _ := ohttp.Encapsulate(cfg, inner(good).Marshal(reportwire.RequestSize))
	for i := range 7 {
		w := post(s, sealed, ohttp.RequestType)
		if w.Code != http.StatusOK {
			t.Fatalf("replay %d: %d", i, w.Code)
		}
	}
	id := newID()
	for range 3 {
		if got := send(t, s, cfg, innerWith(fleet, id, "2026-10-24").Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
			t.Fatalf("retry: %d", got)
		}
	}
	totals, _ := reg.EnergyTotals("2026-10-23", "2026-10-23")
	view, _ := reg.FleetView(now)
	if totals["2026-10-23"].Reports != 1 || len(view.Days) != 1 || view.Days[0].Reports != 1 {
		t.Fatalf("energy %+v fleet %+v", totals, view)
	}
}

// A repeat is answered before any budget is spent, so one captured request
// sent many times cannot crowd out the real reports.
func TestARepeatSpendsNoBudget(t *testing.T) {
	s, reg, cfg := newService(t)
	sealed, _, _ := ohttp.Encapsulate(cfg, inner(fleet).Marshal(reportwire.RequestSize))
	for i := range 2 * int(burst) {
		if w := post(s, sealed, ohttp.RequestType); w.Code != http.StatusOK {
			t.Fatalf("repeat %d: %d", i, w.Code)
		}
	}
	if got := send(t, s, cfg, inner(fleet).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("a new report after repeats: %d", got)
	}
	if view, _ := reg.FleetView(now); len(view.Days) != 1 || view.Days[0].Reports != 2 {
		t.Fatalf("fleet %+v", view)
	}
}

// A request sent before yesterday is refused, so a captured one cannot be
// posted again once its id is forgotten. Yesterday's still counts.
func TestAnOldRequestIsRefused(t *testing.T) {
	s, _, cfg := newService(t)
	if got := send(t, s, cfg, innerWith(fleet, newID(), "2026-10-22").Marshal(reportwire.RequestSize)); got != http.StatusBadRequest {
		t.Fatalf("two days old: %d", got)
	}
	if got := send(t, s, cfg, innerWith(fleet, newID(), "2026-10-23").Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("yesterday: %d", got)
	}
}

// Junk does not spend a budget, and one kind's reports do not spend the
// other's.
func TestJunkSpendsNoBudget(t *testing.T) {
	s, _, cfg := newService(t)
	for range 3 * int(burst) {
		if w := post(s, bytes.Repeat([]byte{9}, 400), ohttp.RequestType); w.Code != http.StatusBadRequest {
			t.Fatalf("junk: %d", w.Code)
		}
	}
	if got := send(t, s, cfg, inner(good).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("a real report after junk: %d", got)
	}
	for i := range int(burst) {
		if got := send(t, s, cfg, inner(good).Marshal(reportwire.RequestSize)); got != http.StatusNoContent && i < int(burst)-1 {
			t.Fatalf("energy %d: %d", i, got)
		}
	}
	if got := send(t, s, cfg, inner(good).Marshal(reportwire.RequestSize)); got != http.StatusTooManyRequests {
		t.Fatalf("energy over budget: %d", got)
	}
	if got := send(t, s, cfg, inner(fleet).Marshal(reportwire.RequestSize)); got != http.StatusNoContent {
		t.Fatalf("fleet beside a spent energy budget: %d", got)
	}
}

// A sender that stops halfway through its body is cut off.
func TestASlowBodyIsCutOff(t *testing.T) {
	s, _, _ := newService(t)
	old := bodyDeadline
	bodyDeadline = 200 * time.Millisecond
	t.Cleanup(func() { bodyDeadline = old })
	srv := httptest.NewServer(s)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "POST /v1/ohttp HTTP/1.1\r\nHost: x\r\nContent-Type: message/ohttp-req\r\nContent-Length: 1000\r\n\r\nabc")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("slow body: %v %v", resp, err)
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
