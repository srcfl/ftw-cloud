package mcp

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

func measurementPage(value any) []byte {
	b, _ := json.Marshal(map[string]any{"encoding": "json", "complete": true, "more": false, "body": value})
	return b
}

func measurementFixture(q protocol.APIRead) (int, []byte) {
	name := strings.Repeat("private-name-", 3)
	var body any
	switch q.Path {
	case "/api/status":
		body = map[string]any{"grid_w": 4000, "load_w": nil, "history_quality": "incomplete", "history_reason": "missing:" + name + ":ev",
			"load_estimate": map[string]any{"watts": nil, "energy_wh": nil, "reason": "incomplete_source_window", "method": "reported_energy_balance_v3", "from_ms": 1000, "to_ms": 2000, "end_age_ms": 4, "timing_basis": "source", "energy_basis": "counters", "extra": name}, "private": name}
	case protocol.AgentAPICatalogPath:
		b, _ := json.Marshal(map[string]any{"troubleshooting": map[string]any{"charger_connections": []any{map[string]any{"id": "private-charger", "driver_name": name, "status": "missing"}}}, "private": name})
		return 200, b
	case "/api/energy/assets":
		body = map[string]any{"assets": []any{map[string]any{"asset_id": name, "device_id": name, "label": name, "kind": "grid_meter"}}}
	case "/api/energy/history":
		body = map[string]any{"scope": "asset", "truncated": true, "points": []any{map[string]any{"asset_id": name, "flow": "grid_import", "bucket_start_ms": 1000, "bucket_len_ms": 300000, "energy_wh": 12, "source": "hardware_counter", "quality": "recovered", "provenance": "counter_gap", "sample_count": 2, "private": name}}}
	case "/api/series/catalog":
		body = map[string]any{"drivers": []string{name}, "metrics": []string{"ev_w"}, "units": map[string]string{"ev_w": "W"}, "private": name}
	case "/api/series":
		body = map[string]any{"driver": name, "metric": "ev_w", "unit": "W", "points": []any{map[string]any{"ts": 2000, "v": 1000, "min": 200, "max": 1800, "n": 2, "resolution_ms": 10000, "first_ms": 1000, "last": 1800, "private": name}}}
	default:
		return 403, []byte(name)
	}
	if doc, ok := body.(map[string]any); ok {
		for _, key := range []string{"address", "serial", "credentials", "password", "token", "identity"} {
			doc[key] = name
		}
	}
	return 200, measurementPage(body)
}

func measurementResult(t *testing.T, a *assistant, view string, args map[string]any) (map[string]any, string) {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	args["view"] = view
	r := profileRPC(t, a, "?profile=public", "tools/call", map[string]any{"name": "measurement_diagnostics", "arguments": args}, false)
	if r.Status != 200 || r.Body["error"] != nil {
		t.Fatal("public measurement tool failed before producing a result")
	}
	result := r.Body["result"].(map[string]any)
	if result["isError"] == true {
		t.Fatal("public measurement tool refused valid evidence")
	}
	b, _ := json.Marshal(result)
	text := string(b)
	for _, value := range []string{strings.Repeat("private-name-", 3), "private-charger", "device_id", "password", "private", "address", "serial", "credentials", "token", "identity"} {
		if strings.Contains(text, value) {
			t.Fatal("restricted measurement data escaped")
		}
	}
	return result["structuredContent"].(map[string]any)["data"].(map[string]any), text
}

func measurementWindow() map[string]any {
	to := time.Now().Add(-time.Minute).UTC()
	return map[string]any{"since": to.Add(-time.Hour).Format(time.RFC3339), "until": to.Format(time.RFC3339)}
}

func TestPublicMeasurementDiagnosticsRetainReasonsAndSafeAssociations(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	b.mu.Lock()
	b.apiReply = measurementFixture
	b.mu.Unlock()
	a := w.connect(b, oauth.ScopeDiagRun)
	data, _ := measurementResult(t, a, "status", nil)
	connections := data["charger_connections"].([]any)
	c := connections[0].(map[string]any)
	if data["load_w"] != nil || data["grid_w"] != float64(4000) || data["history_quality"] != "incomplete" || c["status"] != "missing" || data["history_reason"] != "missing:"+c["source_id"].(string)+":ev" {
		t.Fatal("missing EV evidence lost its reason, source association or null")
	}
	estimate := data["load_estimate"].(map[string]any)
	if estimate["watts"] != nil || estimate["energy_wh"] != nil || estimate["reason"] != "incomplete_source_window" || estimate["method"] != "reported_energy_balance_v3" || estimate["end_age_ms"] != float64(4) || estimate["energy_basis"] != "counters" {
		t.Fatal("interval-quality failure became a measured value or lost its metadata")
	}
	assets, _ := measurementResult(t, a, "assets", nil)
	asset := assets["assets"].([]any)[0].(map[string]any)["asset_id"]
	args := measurementWindow()
	args["asset_id"] = asset
	energy, _ := measurementResult(t, a, "energy", args)
	p := energy["points"].([]any)[0].(map[string]any)
	if energy["truncated"] != true || p["energy_wh"] != float64(12) || p["quality"] != "recovered" || p["provenance"] != "counter_gap" || p["sample_count"] != float64(2) || p["asset_id"] != asset {
		t.Fatal("energy provenance, recovered status or truncation was lost")
	}
	catalog, _ := measurementResult(t, a, "series_catalog", nil)
	source := catalog["source_ids"].([]any)[0]
	metric := catalog["metrics"].([]any)[0].(map[string]any)["metric_id"]
	if source != c["source_id"] {
		t.Fatal("diagnostic source ids did not join across evidence")
	}
	args = measurementWindow()
	args["source_id"], args["metric_id"] = source, metric
	series, _ := measurementResult(t, a, "series", args)
	p = series["points"].([]any)[0].(map[string]any)
	if p["resolution_ms"] != float64(10000) || p["n"] != float64(2) || p["first_ms"] != float64(1000) || p["last"] != float64(1800) {
		t.Fatal("stored aggregate was presented without source bounds or resolution")
	}
	_, _, asked := b.counts()
	for _, request := range asked {
		if strings.HasPrefix(request, protocol.MsgAPIReq+" ") || strings.HasPrefix(request, protocol.MsgCmd+" ") {
			t.Fatal("measurement troubleshooting used a write path")
		}
	}
}

func TestMeasurementDiagnosticsRejectUnsafeOrAmbiguousArgumentsBeforeReading(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	for _, args := range []map[string]any{{"path": "/api/config"}, {"method": "POST"}, {"view": "other"}, {"view": "status", "source_id": "unreturned"}, {"view": "series"}, {"view": "energy", "since": "yesterday", "until": "today"}, {"view": "energy", "since": "2026-01-01T00:00:00Z", "until": "2026-01-03T00:00:00Z"}, {"view": "energy", "limit": 201}} {
		_, failed, _ := a.call("measurement_diagnostics", args)
		if !failed {
			t.Fatal("an invalid measurement request succeeded")
		}
	}
	_, _, asked := b.counts()
	for _, q := range asked {
		if strings.HasPrefix(q, protocol.MsgAPIRead+" ") {
			t.Fatal("an invalid request reached Core")
		}
	}
}

func TestMeasurementDiagnosticsRequireGrantAndFailClosed(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeLiveRead)
	r := profileRPC(t, a, "?profile=public", "tools/call", map[string]any{"name": "measurement_diagnostics", "arguments": map[string]any{}}, true)
	if r.Status != http.StatusForbidden || !strings.Contains(r.Header.Get("WWW-Authenticate"), oauth.ScopeDiagRun) {
		t.Fatal("public diagnostics widened the owner's grant")
	}
	_, _, asked := b.counts()
	if len(asked) != 0 {
		t.Fatal("a refused diagnostic request reached the box")
	}
	a = w.connect(b, oauth.ScopeDiagRun)
	for _, mode := range []string{"refused", "server_error", "partial", "malformed", "stream", "unsupported"} {
		b.mu.Lock()
		b.apiBadSequence = mode == "stream"
		b.apiUnsupported = mode == "unsupported"
		b.apiReply = func(q protocol.APIRead) (int, []byte) {
			switch mode {
			case "refused":
				return 403, []byte(strings.Repeat("restricted", 10))
			case "server_error":
				return 500, []byte(strings.Repeat("restricted", 10))
			case "partial":
				return 200, []byte(`{"encoding":"json","complete":false,"more":true,"body":{"load_w":999}}`)
			case "malformed":
				return 200, []byte(`[]`)
			default:
				return measurementFixture(q)
			}
		}
		b.mu.Unlock()
		result, failed, text := a.call("measurement_diagnostics", nil)
		if !failed || result["structuredContent"] != nil || strings.Contains(text, "restricted") || strings.Contains(text, "999") {
			t.Fatal("failed or partial measurement evidence looked successful or leaked raw data")
		}
	}
}

func TestUnsupportedDiagnosticsAreNotAdvertisedOrSentToCore(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	for _, query := range []string{"", "?profile=public"} {
		listed := profileRPC(t, a, query, "tools/list", nil, false)
		var names []string
		for _, v := range listed.Body["result"].(map[string]any)["tools"].([]any) {
			names = append(names, v.(map[string]any)["name"].(string))
		}
		if !slices.Contains(names, "measurement_diagnostics") {
			t.Fatal("measurement diagnostics are not discoverable")
		}
		for _, name := range []string{"diag_run", "events_list"} {
			if slices.Contains(names, name) {
				t.Fatal("an unsupported operation was advertised")
			}
			r := profileRPC(t, a, query, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}}, false)
			result := r.Body["result"].(map[string]any)
			structured := result["structuredContent"].(map[string]any)
			data := structured["data"].(map[string]any)
			if result["isError"] != true || data["code"] != "E_UNSUPPORTED" || data["available"] != false {
				t.Fatal("a cached unsupported tool did not get an explicit capability error")
			}
			if structured["source"] != "service" {
				t.Fatal("an unsupported operation claimed to be an observation from the box")
			}
		}
	}
	_, _, asked := b.counts()
	if len(asked) != 0 {
		t.Fatal("an unsupported diagnostic was sent to Core")
	}
}

func TestMeasurementReasonAndIdentifierPrivacy(t *testing.T) {
	cc := &callCtx{grant: &oauth.Grant{Subject: oauth.Subject{Home: "home", Agent: "agent-one"}}}
	name := strings.Repeat("private-name-", 3)
	for _, reason := range []string{"time_skew", "invalid_balance", "incomplete_source_window", "missing:" + name + ":ev", "new_reason_" + name} {
		v := cc.measurementReason(reason)
		text, _ := json.Marshal(v)
		if strings.Contains(string(text), name) {
			t.Fatal("a reason exposed a private name")
		}
		if reason == "time_skew" && v != reason {
			t.Fatal("a fixed reason was changed")
		}
	}
	other := &callCtx{grant: &oauth.Grant{Subject: oauth.Subject{Home: "home", Agent: "agent-two"}}}
	if cc.measurementID("source", name) == other.measurementID("source", name) || cc.measurementID("source", name) == cc.measurementID("asset", name) {
		t.Fatal("measurement identifiers crossed grant or object kind")
	}
}
