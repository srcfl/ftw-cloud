package mcp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

// Identifiers are local to this process and grant. No names or reverse map
// survive in Cloud; each selection is resolved against a fresh box catalogue.
var measurementIDKey = func() []byte { key := make([]byte, 32); _, _ = rand.Read(key); return key }()

func (cc *callCtx) measurementID(kind, value string) string {
	if value == "" {
		return ""
	}
	h := hmac.New(sha256.New, measurementIDKey)
	for _, part := range []string{cc.grant.Subject.Home, cc.grant.Subject.Agent, kind, value} {
		_, _ = h.Write([]byte(part + "\x00"))
	}
	return "m_" + hex.EncodeToString(h.Sum(nil)[:12])
}

func measurementTools() []*tool {
	return []*tool{{name: "measurement_diagnostics", title: "Measurement quality and source evidence",
		description: "Read-only, redacted measurement diagnostics from Core: status gives load_w, history_quality, history_reason, load_estimate and saved charger associations; assets and series_catalog list opaque selections for energy and series. Energy gives recorded Wh, quality, provenance and sample counts; series gives stored observations or aggregates with timestamps, count and resolution, never invented raw polls. Energy and series require since/until (RFC 3339 with timezone), at most 24 hours, and return bounded results with truncation stated. Missing values stay null; a recent good value does not repair older gaps. IDs belong to this connection and service instance: refresh the catalogue if unavailable. No addresses, private names, device identifiers, credentials or arbitrary API paths are exposed. Requires the owner's diagnostic grant; the public profile does not add that grant." + dataNote,
		scope:       oauth.ScopeDiagRun, readOnly: true,
		input: object(map[string]any{
			"view":      enum("Which evidence to read; defaults to status", "status", "assets", "energy", "series_catalog", "series"),
			"source_id": map[string]any{"type": "string", "description": "Opaque source id from series_catalog; series only"},
			"metric_id": map[string]any{"type": "string", "description": "Opaque metric id from series_catalog; series only"},
			"asset_id":  map[string]any{"type": "string", "description": "Opaque asset id from assets; omit for system energy"},
			"since":     timeArg("Start of energy or series window, RFC 3339 with timezone"),
			"until":     timeArg("End of energy or series window, RFC 3339 with timezone"),
			"limit":     integer("Maximum energy buckets or series points", 1, 200, 100),
			"bucket":    enum("Energy bucket duration", "5m", "15m", "1h"),
		}), run: measurementDiagnostics}}
}

type measurementArgs struct {
	View   string `json:"view"`
	Source string `json:"source_id"`
	Metric string `json:"metric_id"`
	Asset  string `json:"asset_id"`
	Since  string `json:"since"`
	Until  string `json:"until"`
	Limit  *int   `json:"limit"`
	Bucket string `json:"bucket"`
}

func measurementDiagnostics(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
	var a measurementArgs
	if err := decodeArgs(args, &a); err != nil {
		return nil, userError("Invalid measurement arguments; use the listed fields and values.")
	}
	if a.View == "" {
		a.View = "status"
	}
	if !slices.Contains([]string{"status", "assets", "energy", "series_catalog", "series"}, a.View) {
		return nil, userError("Choose a listed measurement view.")
	}
	windowed := a.View == "energy" || a.View == "series"
	if !windowed && (a.Since != "" || a.Until != "" || a.Limit != nil) || a.View != "energy" && (a.Asset != "" || a.Bucket != "") || a.View != "series" && (a.Source != "" || a.Metric != "") {
		return nil, userError("These arguments do not apply to the selected measurement view.")
	}
	query := map[string]string{}
	if windowed {
		from, e1 := time.Parse(time.RFC3339Nano, a.Since)
		to, e2 := time.Parse(time.RFC3339Nano, a.Until)
		if e1 != nil || e2 != nil || from.UnixMilli() <= 0 || !to.After(from) || to.Sub(from) > 24*time.Hour || to.After(cc.s.now()) {
			return nil, userError("since/until must name a past window of at most 24 hours, with an explicit timezone.")
		}
		limit := 100
		if a.Limit != nil {
			limit = *a.Limit
		}
		if limit < 1 || limit > 200 {
			return nil, userError("limit must be between 1 and 200.")
		}
		query["since"], query["until"], query["limit"] = strconv.FormatInt(from.UnixMilli(), 10), strconv.FormatInt(to.UnixMilli(), 10), strconv.Itoa(limit)
	}
	read := func(path string, q map[string]string) (map[string]any, error) {
		return cc.measurementRead(ctx, path, q)
	}
	switch a.View {
	case "status":
		status, err := read("/api/status", nil)
		if err != nil {
			return nil, err
		}
		if _, present := status["load_w"]; !present {
			return nil, measurementShapeError
		}
		if _, ok := status["history_quality"].(string); !ok {
			return nil, measurementShapeError
		}
		if _, ok := status["history_reason"].(string); !ok {
			return nil, measurementShapeError
		}
		catalog, err := read(protocol.AgentAPICatalogPath, nil)
		if err != nil {
			return nil, err
		}
		out := diagnosticNumbers(status, "load_w grid_w pv_w bat_w ev_w v2x_w")
		out["history_quality"] = diagnosticWord(status["history_quality"], "complete incomplete balance_mismatch")
		out["history_reason"] = cc.measurementReason(status["history_reason"])
		out["load_estimate"] = nil
		if estimate, ok := status["load_estimate"].(map[string]any); ok {
			e := diagnosticNumbers(estimate, "watts energy_wh window_min_w window_max_w from_ms to_ms age_ms end_age_ms source_age_ms")
			e["reason"] = cc.measurementReason(estimate["reason"])
			e["method"] = diagnosticWord(estimate["method"], "reported_energy_balance_v3")
			e["timing_basis"] = diagnosticWord(estimate["timing_basis"], "source receipt mixed")
			e["energy_basis"] = diagnosticWord(estimate["energy_basis"], "power_integral counters mixed")
			out["load_estimate"] = e
		}
		out["charger_connections"] = nil
		if troubleshooting, ok := catalog["troubleshooting"].(map[string]any); ok {
			if connections, ok := troubleshooting["charger_connections"].([]any); ok {
				rows := []any{}
				for _, item := range connections {
					c, ok := item.(map[string]any)
					if !ok {
						return nil, measurementShapeError
					}
					id, _ := c["id"].(string)
					driver, _ := c["driver_name"].(string)
					rows = append(rows, map[string]any{"charger_id": cc.measurementID("charger", id), "source_id": cc.measurementID("source", driver), "status": diagnosticWord(c["status"], "configured missing disabled unverified_ocpp")})
				}
				out["charger_connections"] = rows
			}
		}
		out["note"] = "Live power and the past load-estimate interval are separate. Null binding evidence means this Core did not provide it. A configured name does not prove live equipment or control. Opaque source ids here are diagnostic selections, not control targets."
		return out, nil
	case "assets":
		catalog, err := read("/api/energy/assets", nil)
		if err != nil {
			return nil, err
		}
		assets, ok := catalog["assets"].([]any)
		if !ok {
			return nil, measurementShapeError
		}
		out := []any{}
		for _, item := range assets {
			x, ok := item.(map[string]any)
			if !ok {
				return nil, measurementShapeError
			}
			id, _ := x["asset_id"].(string)
			out = append(out, map[string]any{"asset_id": cc.measurementID("asset", id), "kind": diagnosticWord(x["kind"], "grid_meter pv battery vehicle_charger observed_consumer system")})
		}
		return map[string]any{"assets": out}, nil
	case "energy":
		query["scope"], query["bucket"] = "system", "5m"
		if a.Bucket != "" {
			if !slices.Contains([]string{"5m", "15m", "1h"}, a.Bucket) {
				return nil, userError("Choose a listed energy bucket.")
			}
			query["bucket"] = a.Bucket
		}
		if a.Asset != "" {
			catalog, err := read("/api/energy/assets", nil)
			if err != nil {
				return nil, err
			}
			id, err := cc.resolveMeasurement(catalog["assets"], "asset_id", "asset", a.Asset)
			if err != nil {
				return nil, err
			}
			query["scope"], query["asset_id"] = "asset", id
		}
		page, err := read("/api/energy/history", query)
		if err != nil {
			return nil, err
		}
		out := diagnosticNumbers(page, "schema_version since_ms until_ms requested_bucket_len_ms")
		out["scope"], out["asset_id"], out["truncated"] = query["scope"], a.Asset, diagnosticFlag(page["truncated"])
		rows, ok := page["points"].([]any)
		if !ok {
			return nil, measurementShapeError
		}
		points := []any{}
		for _, item := range rows {
			p, ok := item.(map[string]any)
			if !ok {
				return nil, measurementShapeError
			}
			x := diagnosticNumbers(p, "schema_version bucket_start_ms bucket_len_ms energy_wh sample_count")
			id, _ := p["asset_id"].(string)
			x["asset_id"] = cc.measurementID("asset", id)
			x["flow"] = diagnosticWord(p["flow"], "grid_import grid_export pv_generation battery_charge battery_discharge vehicle_charge vehicle_discharge consumer_use")
			x["source"] = diagnosticWord(p["source"], "hardware_counter power_telemetry source_balance")
			x["quality"] = diagnosticWord(p["quality"], "measured integrated complete incomplete partial recovered invalid gap reset")
			x["provenance"] = diagnosticWord(p["provenance"], "counter counter_gap counter_baseline counter_resumed counter_jump counter_reset counter_resume_fallback counter_reset_fallback power power_baseline power_gap implausible_energy source_interval_balance_v1 source_energy_balance source_energy source_power_integration")
			points = append(points, x)
		}
		out["points"], out["note"] = points, "Energy in Wh retains Core's quality and provenance. Empty or incomplete intervals are not measured zero; no gap is filled here."
		return out, nil
	case "series_catalog", "series":
		catalog, err := read("/api/series/catalog", nil)
		if err != nil {
			return nil, err
		}
		if a.View == "series_catalog" {
			sources, ok := catalog["drivers"].([]any)
			if !ok {
				return nil, measurementShapeError
			}
			metrics, ok := catalog["metrics"].([]any)
			if !ok {
				return nil, measurementShapeError
			}
			ids, ms := []string{}, []any{}
			units, _ := catalog["units"].(map[string]any)
			for _, item := range sources {
				name, ok := item.(string)
				if !ok {
					return nil, measurementShapeError
				}
				ids = append(ids, cc.measurementID("source", name))
			}
			for _, item := range metrics {
				name, ok := item.(string)
				if !ok {
					return nil, measurementShapeError
				}
				ms = append(ms, map[string]any{"metric_id": cc.measurementID("metric", name), "field": diagnosticWord(name, "grid_w load_w pv_w bat_w battery_w ev_w v2x_w bat_soc battery_soc"), "unit": diagnosticWord(units[name], "W Wh A V Hz s ms °C ratio fraction percent")})
			}
			return map[string]any{"source_ids": ids, "metrics": ms, "note": "Catalogue lists sources and metrics independently; an empty selected pair means no stored rows, not measured zero."}, nil
		}
		driver, err := cc.resolveMeasurement(catalog["drivers"], "", "source", a.Source)
		if err != nil {
			return nil, err
		}
		metric, err := cc.resolveMeasurement(catalog["metrics"], "", "metric", a.Metric)
		if err != nil {
			return nil, err
		}
		query["driver"], query["metric"], query["points"] = driver, metric, query["limit"]
		delete(query, "limit")
		page, err := read("/api/series", query)
		if err != nil {
			return nil, err
		}
		out := diagnosticNumbers(page, "since until")
		out["source_id"], out["metric_id"] = a.Source, a.Metric
		out["unit"] = diagnosticWord(page["unit"], "W Wh A V Hz s ms °C ratio fraction percent")
		rows, ok := page["points"].([]any)
		if !ok {
			return nil, measurementShapeError
		}
		points := []any{}
		for _, item := range rows {
			p, ok := item.(map[string]any)
			if !ok {
				return nil, measurementShapeError
			}
			points = append(points, diagnosticNumbers(p, "ts v min max n resolution_ms first_ms last"))
		}
		out["points"], out["note"] = points, "These are stored observations or aggregates. Read resolution_ms, n and first_ms; bounds alone do not prove continuous coverage. No missing point becomes zero."
		return out, nil
	}
	return nil, measurementShapeError
}

const measurementShapeError = userError("Core did not return complete measurement evidence in the expected format. Check its version and retry a narrower read; no partial evidence was returned.")

// This helper accepts only fixed reads. It never returns arbitrary response
// text, error bodies, headers, archive contents or incomplete byte pages.
func (cc *callCtx) measurementRead(ctx context.Context, path string, query map[string]string) (map[string]any, error) {
	if !slices.Contains([]string{protocol.AgentAPICatalogPath, "/api/status", "/api/energy/assets", "/api/energy/history", "/api/series/catalog", "/api/series"}, path) {
		return nil, measurementShapeError
	}
	c, err := cc.conn(ctx)
	if err != nil {
		return nil, userError("Measurement diagnostics could not reach the granted box. Check homes_list and health_get.")
	}
	ctx, cancel := context.WithTimeout(ctx, protocol.AgentAPIReadTimeout)
	defer cancel()
	head, body, err := c.apiRead(ctx, protocol.APIRead{Path: path, Query: query, MaxBytes: protocol.AgentAPIPageBytes})
	if err != nil {
		return nil, userError("Measurement diagnostics are unavailable or refused. Check Core's version and the owner's diagnostic grant; no driver fault is inferred.")
	}
	if head.Status < 200 || head.Status >= 300 {
		return nil, userError(fmt.Sprintf("Core refused the measurement read %s (HTTP %d). No response text or partial evidence was exposed.", path, head.Status))
	}
	var page map[string]any
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	if !json.Valid(body) || d.Decode(&page) != nil || page == nil {
		return nil, measurementShapeError
	}
	if path == protocol.AgentAPICatalogPath {
		return page, nil
	}
	if page["encoding"] != "json" || page["complete"] != true || page["more"] != false {
		return nil, measurementShapeError
	}
	data, ok := page["body"].(map[string]any)
	if !ok {
		return nil, measurementShapeError
	}
	return data, nil
}

func (cc *callCtx) resolveMeasurement(items any, field, kind, id string) (string, error) {
	if id == "" {
		return "", userError("Choose an opaque id returned by this measurement catalogue.")
	}
	rows, ok := items.([]any)
	if !ok {
		return "", measurementShapeError
	}
	for _, item := range rows {
		name, ok := item.(string)
		if field != "" {
			m, good := item.(map[string]any)
			if !good {
				return "", measurementShapeError
			}
			name, ok = m[field].(string)
		}
		if !ok {
			return "", measurementShapeError
		}
		if cc.measurementID(kind, name) == id {
			return name, nil
		}
	}
	return "", userError("That measurement id is unavailable. Refresh assets or series_catalog for this connection and choose a returned id.")
}

func diagnosticNumbers(in map[string]any, keys string) map[string]any {
	out := map[string]any{}
	for _, key := range strings.Fields(keys) {
		v := in[key]
		switch v.(type) {
		case json.Number:
			out[key] = v
		default:
			out[key] = nil
		}
	}
	return out
}
func diagnosticFlag(v any) any {
	if flag, ok := v.(bool); ok {
		return flag
	}
	return nil
}
func diagnosticWord(v any, allowed string) string {
	s, ok := v.(string)
	if ok && slices.Contains(strings.Fields(allowed), s) {
		return s
	}
	return "unknown"
}
func (cc *callCtx) measurementReason(v any) any {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	if s == "" {
		return ""
	}
	if diagnosticWord(s, "no_telemetry no_pv_source missing_config invalid_balance time_skew pv_time_skew nonfinite_pv_sum configured_pv_without_measurement_source charger_source_time_unavailable missing_source_window incomplete_source_window stale_source_window unknown_topology") != "unknown" {
		return s
	}
	first, last := strings.IndexByte(s, ':'), strings.LastIndexByte(s, ':')
	if first > 0 && last > first && slices.Contains([]string{"missing", "stale", "offline", "invalid_sign", "unknown_power", "nonfinite", "future"}, s[:first]) && slices.Contains([]string{"meter", "pv", "battery", "ev", "v2x_charger"}, s[last+1:]) {
		return s[:first] + ":" + cc.measurementID("source", s[first+1:last]) + s[last:]
	}
	if first > 0 && slices.Contains([]string{"duplicate_flow", "duplicate_charger"}, s[:first]) {
		return s[:first] + ":" + cc.measurementID("source", s[first+1:])
	}
	return "unknown_reason"
}

func unsupportedDiagnostic(name string) bool { return name == "diag_run" || name == "events_list" }
