package server

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/ohttp"
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

// Box to relay to gateway to totals. The box half is what Core sends: the
// key configuration from /.well-known/ohttp-gateway, the one inner request,
// padded. The relay forwards only the body and its type, and never sees the
// report. ftwcloudd adds it to the date's totals and answers a sealed 204.
func TestAnEnergyReportReachesTheTotalsThroughARelay(t *testing.T) {
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
	for i := range 3 {
		body, _ := json.Marshal(report)
		inner := ohttp.Request{Method: energywire.Method, Scheme: energywire.Scheme, Authority: energywire.Authority, Path: energywire.Path, Content: body}.Marshal(energywire.RequestSize)
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
		if got, err := ohttp.ParseResponse(msg); err != nil || got.Status != http.StatusNoContent || len(msg) != energywire.ResponseSize {
			t.Fatalf("report %d: %+v %v", i, got, err)
		}
		if bytes.Contains(seen[i], []byte("kwh")) || bytes.Contains(seen[i], []byte(yesterday)) {
			t.Fatal("the relay saw the report")
		}
	}
	totals, err := s.Registry.EnergyTotals(yesterday, yesterday)
	day := totals[yesterday]
	if err != nil || day.Reports != 3 || day.Sums != [6]int64{36, 90, 12, 27, 24, 0} {
		t.Fatalf("totals %+v %v", day, err)
	}
	if len(seen[0]) != len(seen[1]) {
		t.Fatal("two reports differ in length on the relay")
	}
}
