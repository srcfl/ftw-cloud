package mcp

import (
	"net/http"
	"strings"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

func TestAnAssistantReadsTheDiagnosticAPIThroughItsBox(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	res, isErr, text := a.call("api_catalog", nil)
	if isErr || !strings.Contains(text, "/api/energy/history") || !strings.Contains(text, "/api/series") || !strings.Contains(text, "/api/mpc/diagnose/at") {
		t.Fatalf("diagnostic catalogue: %+v %s", res, text)
	}
	_, isErr, text = a.call("api_read", map[string]any{"path": "/api/energy/assets"})
	if isErr || !strings.Contains(text, "opaque-asset") {
		t.Fatalf("assets: %s", text)
	}
	res, isErr, text = a.call("api_read", map[string]any{"path": "/api/energy/history", "query": map[string]string{"asset_id": "opaque-asset", "scope": "asset", "bucket": "5m", "since": "1792328000000", "until": "1792328300000"}})
	if isErr || !strings.Contains(text, `"energy_wh":12`) || !strings.Contains(text, `"counter":9007199254740993`) || !strings.Contains(text, `"provenance":"counter"`) {
		t.Fatalf("energy ledger: %+v %s", res, text)
	}
	_, _, asked := b.counts()
	joined := strings.Join(asked, "\n")
	if !strings.Contains(joined, protocol.MsgAPIRead+" ") || !strings.Contains(joined, "1792328000000") || strings.Contains(joined, protocol.MsgAPIReq+" ") {
		t.Fatalf("wrong box reads: %s", joined)
	}
	for _, args := range []map[string]any{
		{"path": "/api/config"},
		{"path": "/api/scan"},
		{"path": "/api/energy/history", "method": "POST"},
		{"path": "/api/energy/history?scope=system"},
		{"path": "/api/series", "query": map[string]string{"format": "csv"}},
		{"path": "/api/energy/history", "max_bytes": 1048577},
	} {
		if _, isErr, text := a.call("api_read", args); !isErr {
			t.Errorf("invalid diagnostic request accepted: %+v %s", args, text)
		}
	}
}

func TestDiagnosticAPITokenNeedsTheDataScopeToo(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	_, isErr, text := a.call("api_catalog", nil)
	if isErr || strings.Contains(text, "/api/energy/history") {
		t.Fatalf("catalogue lists ungranted data: %s", text)
	}
	r := a.rpc("tools/call", map[string]any{"name": "api_read", "arguments": map[string]any{"path": "/api/energy/history"}}, true)
	if r.Status != http.StatusForbidden {
		t.Fatalf("data scope should require a new grant: %d %+v", r.Status, r.Body)
	}
	_, _, asked := b.counts()
	if len(asked) != 0 {
		t.Fatalf("a denied request reached the box: %+v", asked)
	}
}

func TestDiagnosticAPITruncationReturnsNoPartialResult(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	res, isErr, text := a.call("api_read", map[string]any{"path": "/api/status", "max_bytes": 4096})
	if !isErr || !strings.Contains(text, "max_bytes") || res["structuredContent"] != nil {
		t.Fatalf("truncated answer: %+v %s", res, text)
	}
}

func TestDiagnosticAPISkippedChunkReturnsNoPartialResult(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	b.mu.Lock()
	b.apiBadSequence = true
	b.mu.Unlock()
	res, isErr, text := a.call("api_read", map[string]any{"path": "/api/energy/history"})
	if !isErr || !strings.Contains(text, "incomplete") || res["structuredContent"] != nil {
		t.Fatalf("incomplete stream: %+v %s", res, text)
	}
}

func TestDiagnosticAPISaysWhatAnOlderBoxNeeds(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	b.mu.Lock()
	b.apiUnsupported = true
	b.mu.Unlock()
	_, isErr, text := a.call("api_read", map[string]any{"path": "/api/energy/history"})
	if !isErr || !strings.Contains(text, "Core version") || !strings.Contains(text, "health_get") {
		t.Fatalf("older box: %s", text)
	}
	if _, isErr, text := a.call("health_get", nil); isErr {
		t.Fatalf("typed reads stopped working: %s", text)
	}
}

func TestDiagnosticAPITimesAcceptTheUsersTimezone(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	_, isErr, text := a.call("api_read", map[string]any{"path": "/api/mpc/diagnose/at", "query": map[string]string{"ts": "2026-10-18T15:00:00+02:00"}})
	if isErr {
		t.Fatal(text)
	}
	_, _, asked := b.counts()
	if !strings.Contains(strings.Join(asked, "\n"), "1792328400000") {
		t.Fatalf("incident time did not reach the box in milliseconds: %+v", asked)
	}
	if _, isErr, text := a.call("api_read", map[string]any{"path": "/api/mpc/diagnose/history", "query": map[string]string{"since": "yesterday"}}); !isErr {
		t.Fatalf("an ambiguous time silently selected another range: %s", text)
	}
}
