package mcp

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

func TestSetupUsesAnExplicitGrantThroughOAuthAndNoise(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	scopes := append(slices.Clone(oauth.ReadScopes), oauth.ScopeSetupWrite)
	a := w.connect(b, strings.Join(scopes, " "), scopes...)
	for name, args := range map[string]map[string]any{
		"setup_schema": {}, "setup_status": {},
		"setup_edit":    {"revision": 0, "operations": []any{map[string]any{"op": "replace", "path": "/drivers/0/name", "value": "Garage meter"}}},
		"setup_commit":  {"revision": 1, "base_revision": 4, "sha256": strings.Repeat("a", 64), "confirmed": true},
		"setup_restart": {"saved_revision": 5, "sha256": strings.Repeat("a", 64), "confirmed": true},
	} {
		_, isErr, text := a.call(name, args)
		if isErr || !strings.Contains(text, `"hardware_verified":false`) {
			t.Fatal(name, text)
		}
		if name == "setup_edit" && !strings.Contains(text, "Garage meter") {
			t.Fatal("patch did not survive the Noise session", text)
		}
	}
	_, isErr, text := a.call("setup_commit", map[string]any{"revision": 1, "base_revision": 4, "sha256": strings.Repeat("a", 64), "confirmed": false})
	if !isErr || !strings.Contains(text, `"status":400`) {
		t.Fatal("denied commit was reported as success", text)
	}
	_, _, asked := b.counts()
	if strings.Contains(strings.Join(asked, "\n"), protocol.MsgAPIReq+" ") {
		t.Fatal("setup used an owner's generic API passthrough")
	}
}

func TestLostSetupAnswerReportsUnknownAndHowToResume(t *testing.T) {
	for _, name := range []string{"setup_commit", "setup_restart"} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			b := w.connectBox()
			scopes := append(slices.Clone(oauth.ReadScopes), oauth.ScopeSetupWrite)
			a := w.connect(b, strings.Join(scopes, " "), scopes...)
			b.mu.Lock()
			b.setupLoseReply = true
			b.mu.Unlock()
			_, _, text := a.call(name, map[string]any{"revision": 1, "base_revision": 4, "saved_revision": 5, "sha256": strings.Repeat("a", 64), "confirmed": true})
			if !strings.Contains(text, `"state":"unknown"`) || !strings.Contains(text, "setup_status") || !strings.Contains(text, "last_commit") || strings.Contains(text, "Retry the read") || strings.Contains(text, "max_bytes") {
				t.Fatal("lost setup reply hid its outcome and recovery", text)
			}
		})
	}
}

func TestSetupScopeUpgradePreservesReadsAndSignalsChatGPT(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeConfigRead, oauth.ScopeConfigRead)
	for _, modern := range []bool{false, true} {
		r := a.rpc("tools/call", map[string]any{"name": "setup_edit", "arguments": map[string]any{"revision": 0, "patch": map[string]any{}}}, modern)
		if r.Status != http.StatusForbidden {
			t.Fatal(r.Status, r.Body)
		}
		result, _ := r.Body["result"].(map[string]any)
		if result["isError"] != true {
			t.Fatal("missing tool auth error", r.Body)
		}
		meta, _ := result["_meta"].(map[string]any)
		challenge := meta["mcp/www_authenticate"].([]any)[0].(string)
		if challenge != r.Header.Get("WWW-Authenticate") || !strings.Contains(challenge, `scope="ftw.config.read ftw.diag.run ftw.setup.write"`) {
			t.Fatal(challenge)
		}
	}
	if _, _, asked := b.counts(); len(asked) != 0 {
		t.Fatal("a denied setup reached the box", asked)
	}
	for _, tool := range w.mcp.listing() {
		if tool["name"] == "setup_edit" {
			schemes := tool["securitySchemes"].([]map[string]any)
			if !slices.Equal(schemes[0]["scopes"].([]string), []string{oauth.ScopeDiagRun, oauth.ScopeSetupWrite}) {
				t.Fatal(schemes)
			}
		}
	}
}

func TestSetupWriteWithoutDiagnosticReadsRequestsBothRights(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeSetupWrite, oauth.ScopeSetupWrite)
	r := a.rpc("tools/call", map[string]any{"name": "setup_edit", "arguments": map[string]any{"revision": 0, "patch": map[string]any{}}}, false)
	if r.Status != http.StatusForbidden || !strings.Contains(r.Header.Get("WWW-Authenticate"), `scope="ftw.diag.run ftw.setup.write"`) {
		t.Fatal("a write-only grant bypassed the setup read requirement", r.Status, r.Body)
	}
	if _, _, asked := b.counts(); len(asked) != 0 {
		t.Fatal("a write-only setup reached the box", asked)
	}
}
