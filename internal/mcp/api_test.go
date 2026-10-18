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
	if res["structuredContent"].(map[string]any)["source"] != "box" {
		t.Fatal("the catalogue did not identify its box source")
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
		{"path": "/api/energy/history", "method": "POST"},
		{"path": "/api/energy/history?scope=system"},
		{"path": "/api/energy/history", "max_bytes": 1048577},
		{"path": "/api/energy/history", "offset": -1},
		{"path": "/api/energy/history", "if_sha256": "bad"},
		{"path": "/api/../config"},
	} {
		if _, isErr, text := a.call("api_read", args); !isErr {
			t.Errorf("invalid diagnostic request accepted: %+v %s", args, text)
		}
	}
}

func TestDiagnosticGrantCoversAllTechnicalReadsWithoutExtraScopes(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	for _, path := range []string{protocol.AgentAPICatalogPath, "/api/config", "/api/drivers/driver-192.168.1.9/source", "/api/logs", "/api/future/read", "/api/series"} {
		_, isErr, text := a.call("api_read", map[string]any{"path": path, "query": map[string]string{"future_parameter": "yes"}})
		if isErr {
			t.Fatalf("diagnostic read %s: %s", path, text)
		}
	}
	_, isErr, text := a.call("api_catalog", nil)
	if isErr || !strings.Contains(text, "/api/energy/history") || !strings.Contains(text, "https://github.com/srcfl/ftw/tree/v0.151.0-beta.1") || !strings.Contains(text, "reproduction steps") {
		t.Fatalf("debug context missing: %s", text)
	}
	_, _, asked := b.counts()
	if !strings.Contains(strings.Join(asked, "\n"), protocol.AgentAPICatalogPath) {
		t.Fatal("catalogue did not come from the connected Core")
	}
	// A deliberately narrower token still cannot use the diagnostic grant.
	narrow := w.connect(b, oauth.ScopeHistoryRead)
	r := narrow.rpc("tools/call", map[string]any{"name": "api_read", "arguments": map[string]any{"path": "/api/energy/history"}}, true)
	if r.Status != http.StatusForbidden {
		t.Fatalf("diagnostic grant not checked: %d", r.Status)
	}
}

func TestDiagnosticPageArgumentsAndTechnicalTextSurviveOAuthAndNoise(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	digest := strings.Repeat("a", 64)
	_, isErr, text := a.call("api_read", map[string]any{"path": "/api/test/pages", "offset": int64(1048576), "if_sha256": digest})
	if isErr || !strings.Contains(text, "192.168.1.9") || !strings.Contains(text, "9007199254740993") || !strings.Contains(text, `"offset":1048576`) || !strings.Contains(text, digest) {
		t.Fatalf("page: %s", text)
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

func TestDiagnosticArchiveMemberArgumentReachesTheBox(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeDiagRun)
	_, isErr, text := a.call("api_read", map[string]any{"path": "/api/test/archive", "archive_member": "logs/global.log"})
	if isErr || !strings.Contains(text, "logs/global.log") {
		t.Fatalf("archive member: %s", text)
	}
}
