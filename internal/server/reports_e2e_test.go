package server

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
	"github.com/srcfl/ftw/go/protocol/ohttp"
	"github.com/srcfl/ftw/go/protocol/reportwire"
)

func testGateway(t *testing.T) *ohttp.Gateway {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	g, err := ohttp.NewGateway(ohttp.Key{ID: 3, Private: k})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// Box to relay to gateway to totals, for both reports. The box half is what
// Core sends: the key configuration from /.well-known/ohttp-gateway, each
// report alone in the one padded inner request. The relay forwards only the
// body and its type, never sees a report, and sees one length. ftwcloudd adds
// each to its own day totals and answers a sealed 204.
func TestBothReportsReachTheirTotalsThroughARelay(t *testing.T) {
	s, _ := newServer(t)
	cloud := httptest.NewServer(s.Handler())
	defer cloud.Close()

	var seen [][]byte
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, body)
		resp, err := http.Post(cloud.URL+"/v1/ohttp", r.Header.Get("Content-Type"), bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer relay.Close()

	resp, err := http.Get(cloud.URL + "/.well-known/ohttp-gateway")
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	configs, err := ohttp.ParseKeys(keys)
	if err != nil || len(configs) != 1 || resp.Header.Get("Content-Type") != ohttp.KeysType {
		t.Fatalf("key configuration %x %v", keys, err)
	}

	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	report := energywire.Report{Schema: energywire.Schema, Date: yesterday, PVGeneration: 12, GridImport: 30, GridExport: 4, BatteryCharge: 9, BatteryDischarge: 8}
	energyBody, _ := json.Marshal(report)
	fleetBody, _ := json.Marshal(fleetwire.Report{Schema: fleetwire.Schema, Version: "v0.146.0", Channel: "stable", Drivers: []string{"sungrow"}, Battery: "5-15", Zone: "SE4", Age: "1-6m"})
	// Three energy reports and two fleet reports, each alone.
	for i, body := range [][]byte{energyBody, fleetBody, energyBody, fleetBody, energyBody} {
		id := make([]byte, reportwire.IDBytes)
		_, _ = rand.Read(id)
		inner, ok := reportwire.Request(reportwire.Report{ID: id, Day: time.Now().UTC().Format(time.DateOnly), Body: body})
		if !ok {
			t.Fatal("report does not fit")
		}
		sealed, reader, err := ohttp.Encapsulate(configs[0], inner)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.Post(relay.URL, ohttp.RequestType, bytes.NewReader(sealed))
		if err != nil {
			t.Fatal(err)
		}
		answer, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != ohttp.ResponseType {
			t.Fatalf("relay got %d %v", resp.StatusCode, resp.Header)
		}
		msg, err := reader.Open(answer)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ohttp.ParseResponse(msg); err != nil || got.Status != http.StatusNoContent || len(msg) != reportwire.ResponseSize {
			t.Fatalf("report %d: %+v %v", i, got, err)
		}
		if bytes.Contains(seen[i], []byte("kwh")) || bytes.Contains(seen[i], []byte(yesterday)) || bytes.Contains(seen[i], []byte("sungrow")) {
			t.Fatal("the relay saw the report")
		}
	}
	totals, err := s.Registry.EnergyTotals(yesterday, yesterday)
	day := totals[yesterday]
	if err != nil || day.Reports != 3 || day.Sums != [6]int64{36, 90, 12, 27, 24, 0} {
		t.Fatalf("totals %+v %v", day, err)
	}
	for _, b := range seen {
		if len(b) != len(seen[0]) {
			t.Fatal("reports differ in length on the relay")
		}
	}
	// The fleet reports land where /v1/fleet/public reads them.
	view, err := s.Registry.FleetView(time.Now())
	if err != nil || len(view.Days) != 1 || view.Days[0].Reports != 2 || view.Days[0].Drivers["sungrow"] != 2 {
		t.Fatalf("fleet %+v %v", view, err)
	}
}
