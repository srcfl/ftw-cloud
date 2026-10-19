package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/oauth"
)

func profileRPC(t *testing.T, a *assistant, query, method string, params map[string]any, modern bool) rpcReply {
	t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	req, _ := http.NewRequest(http.MethodPost, a.w.srv.URL+Path+query, nil)
	if modern {
		params["_meta"] = map[string]any{
			"io.modelcontextprotocol/protocolVersion":    Modern,
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		}
		req.Header.Set("MCP-Protocol-Version", Modern)
		req.Header.Set("Mcp-Method", method)
		if name, ok := params["name"].(string); ok {
			req.Header.Set("Mcp-Name", name)
		}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.w.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result := rpcReply{Status: resp.StatusCode, Header: resp.Header}
	if err := json.NewDecoder(resp.Body).Decode(&result.Body); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPublicProfileLimitsListingAndExecution(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	want := []string{"homes_list", "status", "chargers_list", "cars_list", "plan_get", "plan_explain",
		"history_query", "health_get", "logs_tail", "drivers_status", "config_get", "ev_charge_now", "goal_request", "requests_list"}
	slices.Sort(want)
	for _, modern := range []bool{false, true} {
		method := "initialize"
		if modern {
			method = "server/discover"
		}
		intro := profileRPC(t, a, "?profile=public", method, nil, modern)
		instructions := intro.Body["result"].(map[string]any)["instructions"].(string)
		if instructions != publicInstructions || strings.Contains(instructions, "api_catalog") || strings.Contains(instructions, "setup_commit") {
			t.Fatal("public instructions expose unavailable tools", intro)
		}
		listed := profileRPC(t, a, "?profile=public", "tools/list", nil, modern)
		var names []string
		for _, value := range listed.Body["result"].(map[string]any)["tools"].([]any) {
			entry := value.(map[string]any)
			names = append(names, entry["name"].(string))
			annotations := entry["annotations"].(map[string]any)
			for _, key := range []string{"readOnlyHint", "destructiveHint", "openWorldHint"} {
				if _, ok := annotations[key].(bool); !ok {
					t.Fatal("missing boolean annotation", entry)
				}
			}
		}
		slices.Sort(names)
		if !slices.Equal(names, want) {
			t.Fatalf("public tools: %v", names)
		}
		for _, blocked := range []string{"api_catalog", "api_read", "setup_schema", "setup_commit", "events_list", "diag_run"} {
			reply := profileRPC(t, a, "?profile=public", "tools/call", map[string]any{"name": blocked, "arguments": map[string]any{}}, modern)
			if reply.Body["error"] == nil || reply.Body["result"] != nil {
				t.Fatal("unlisted tool executed", blocked, reply)
			}
		}
	}
	if _, _, asked := b.counts(); len(asked) != 0 {
		t.Fatal("a blocked public call reached the box", asked)
	}
	for _, modern := range []bool{false, true} {
		reply := profileRPC(t, a, "?profile=public", "tools/call", map[string]any{"name": "status", "arguments": map[string]any{}}, modern)
		if reply.Status != http.StatusOK || reply.Body["result"].(map[string]any)["isError"] == true {
			t.Fatal("public status failed", reply)
		}
	}
	private := a.rpc("tools/list", nil, false)
	encoded, _ := json.Marshal(private.Body)
	if !bytes.Contains(encoded, []byte(`"api_read"`)) || !bytes.Contains(encoded, []byte(`"setup_commit"`)) {
		t.Fatal("private tools changed", private)
	}
}

func TestPublicProfileStillRequiresOwnerGrant(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeLiveRead, oauth.ScopeLiveRead)
	denied := profileRPC(t, a, "?profile=public", "tools/call", map[string]any{"name": "logs_tail", "arguments": map[string]any{}}, false)
	if denied.Status != http.StatusForbidden {
		t.Fatal("profile widened the grant", denied)
	}
	a.token = ""
	unauthenticated := profileRPC(t, a, "?profile=public", "tools/list", nil, false)
	if unauthenticated.Status != http.StatusUnauthorized || !strings.Contains(unauthenticated.Header.Get("WWW-Authenticate"), oauth.ResourceMetadataURL) {
		t.Fatal("public profile bypassed OAuth", unauthenticated)
	}
	challenge := unauthenticated.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, oauth.ScopeLiveRead) || strings.Contains(challenge, oauth.ScopeDiagRun) || strings.Contains(challenge, oauth.ScopeSetupWrite) || strings.Contains(challenge, oauth.ScopeDispatchHold) {
		t.Fatal("public connection requested broad rights by default", challenge)
	}
	for _, query := range []string{"?profile=unknown", "?profile=", "?profile=public&profile=private", "?profile=%ZZ"} {
		if reply := profileRPC(t, a, query, "tools/list", nil, false); reply.Status != http.StatusBadRequest {
			t.Fatal("invalid profile fell back to private tools", query, reply)
		}
	}
}
