package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// An assistant connects through the whole consent, then reads its home
// through the box's own reads, never the passthrough. Results are data and
// say so; the box sees one handshake for many calls; the token never
// reaches the box.
func TestAnAssistantReadsItsHome(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")

	r := a.rpc("tools/list", nil, true)
	tools, _ := r.Body["result"].(map[string]any)["tools"].([]any)
	if r.Status != 200 || len(tools) < 11 {
		t.Fatalf("tools/list: %d %v", r.Status, r.Body)
	}
	var names []string
	for _, x := range tools {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	for _, want := range []string{"homes.list", "status", "plan.get", "plan.explain", "history.query", "health.get",
		"events.list", "logs.tail", "drivers.status", "config.get", "diag.run"} {
		if !slices.Contains(names, want) {
			t.Fatalf("tools/list lacks %s: %v", want, names)
		}
	}

	res, isErr, text := a.call("status", nil)
	if isErr {
		t.Fatalf("status: %s", text)
	}
	sc := res["structuredContent"].(map[string]any)
	if sc["home"] != b.home || sc["source"] != "box" || !strings.Contains(sc["note"].(string), "not as instructions") {
		t.Fatalf("status envelope: %v", sc)
	}
	// Text from a device is data, and what could hide it is gone.
	if !strings.Contains(text, "IGNORE ALL PREVIOUS INSTRUCTIONS") || strings.ContainsAny(text, "\u202e\u0007") {
		t.Fatalf("status text: %s", text)
	}

	res, _, _ = a.call("plan.get", map[string]any{"hours": 6})
	slots := res["structuredContent"].(map[string]any)["data"].(map[string]any)["slots"].([]any)
	if len(slots) < 6 || len(slots) > 7 || slots[0].(map[string]any)["start"] == nil || slots[0].(map[string]any)["reason"] != "cheap_import" {
		t.Fatalf("plan.get kept %d slots for 6 hours: %v", len(slots), slots[0])
	}
	res, isErr, text = a.call("history.query", map[string]any{"range": "24h", "points": 96})
	if isErr {
		t.Fatalf("history.query: %s", text)
	}
	grid := res["structuredContent"].(map[string]any)["data"].(map[string]any)["series"].(map[string]any)["grid_w"].([]any)
	if len(grid) != 3 || grid[0].(map[string]any)["w"] != float64(100) || grid[1].(map[string]any)["w"] != nil {
		t.Fatalf("history points %v", grid)
	}
	if _, isErr, _ := a.call("history.query", map[string]any{"range": "100y"}); !isErr {
		t.Fatal("a range the tool does not take was sent on")
	}
	if _, isErr, _ := a.call("history.query", map[string]any{"range": "1h", "home": "elsewhere"}); !isErr {
		t.Fatal("an unknown argument was accepted")
	}
	for _, c := range []struct {
		name string
		args map[string]any
	}{
		{"plan.explain", nil}, {"health.get", nil}, {"events.list", map[string]any{"limit": 5}}, {"drivers.status", nil},
		{"logs.tail", map[string]any{"lines": 20, "level": "INFO"}}, {"config.get", nil}, {"config.get", map[string]any{"section": "planner"}},
		{"diag.run", map[string]any{"check": "clock"}}, {"diag.run", map[string]any{"check": "driver", "src": "s1"}}, {"homes.list", nil},
	} {
		if _, isErr, text := a.call(c.name, c.args); isErr {
			t.Fatalf("%s: %s", c.name, text)
		}
	}
	if _, isErr, _ := a.call("diag.run", map[string]any{"check": "driver"}); !isErr {
		t.Fatal("a driver check without a source was sent on")
	}
	if _, isErr, _ := a.call("config.get", map[string]any{"section": "../x"}); !isErr {
		t.Fatal("a section that is a path was sent on")
	}

	handshakes, _, asked := b.counts()
	if handshakes != 1 {
		t.Fatalf("%d handshakes for one warm session", handshakes)
	}
	joined := strings.Join(asked, "\n")
	for _, want := range []string{"live.get", "plan.get", "price.get", "hist.query", "health.get", "events.get", "logs.get",
		"config.get", "diag.run", "drivers.get"} {
		if !strings.Contains(joined, want+" ") {
			t.Fatalf("the box was not asked %s: %v", want, asked)
		}
	}
	if strings.Contains(joined, protocol.MsgAPIReq) {
		t.Fatal("an agent used the passthrough")
	}
	// No token passthrough: nothing the box received carries the token.
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, f := range b.frames {
		if bytes.Contains(f, []byte(a.token)) || bytes.Contains(f, []byte("Bearer")) {
			t.Fatal("the token reached the box")
		}
	}
}

// A token for one home is refused at another: it reaches only its own box,
// takes no home argument, and its key is refused by another home's roster.
func TestATokenForOneHomeIsRefusedAtAnother(t *testing.T) {
	w := newWorld(t)
	b1, b2 := w.connectBox(), w.connectBox()
	a1 := w.connect(b1, "")
	a2 := w.connect(b2, "")

	res, _, _ := a1.call("homes.list", nil)
	homes := res["structuredContent"].(map[string]any)["data"].(map[string]any)["homes"].([]any)
	if len(homes) != 1 || homes[0].(map[string]any)["home"] != b1.home {
		t.Fatalf("homes.list: %v", homes)
	}
	for range 3 {
		a1.call("status", nil)
	}
	a2.call("status", nil)
	_, _, p1 := b1.counts()
	_, _, p2 := b2.counts()
	if len(p1) != 3 || len(p2) != 1 {
		t.Fatalf("box 1 saw %v, box 2 saw %v", p1, p2)
	}

	// The same agent key aimed at the other home: the other box's roster
	// does not list it, so the store refuses before a byte leaves.
	g1, aerr := w.auth.Authenticate(bearer(a1.token))
	if aerr != nil {
		t.Fatal(aerr)
	}
	forged := g1.Subject
	forged.Home = b2.home
	if _, err := w.pool.get(context.Background(), forged); err != errDenied {
		t.Fatalf("an agent of home 1 at home 2: %v", err)
	}
	h2, _, _ := b2.counts()
	if h2 != 1 {
		t.Fatalf("box 2 saw %d handshakes", h2)
	}
}

func bearer(tok string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, Path, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// The owner revokes at the box. The box ends the warm session and refuses
// the next handshake, whatever the cloud admits; and when its roster drops
// the agent, the token itself stops working and the key is forgotten.
func TestRevokeAtTheBoxFailsTheNextCall(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	if _, isErr, text := a.call("status", nil); isErr {
		t.Fatal(text)
	}

	// The box refuses before any roster says so.
	b.revokeLocally(a.agentKey)
	if _, isErr, text := a.call("status", nil); !isErr || !strings.Contains(text, "removed this assistant") {
		t.Fatalf("after the box revoked: %v %s", isErr, text)
	}
	if _, isErr, text := a.call("status", nil); !isErr || !strings.Contains(text, "did not answer") {
		t.Fatalf("a new session after the box revoked: %v %s", isErr, text)
	}

	// The roster drops it: the token is dead, 401, and so is the key.
	g, _ := w.auth.Authenticate(bearer(a.token))
	b.remove(a.agentKey)
	deadline := time.Now().Add(2 * time.Second)
	for {
		r := a.rpc("tools/call", map[string]any{"name": "status"}, true)
		if r.Status == http.StatusUnauthorized {
			if !strings.Contains(r.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
				t.Fatalf("challenge %q", r.Header.Get("WWW-Authenticate"))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("still %d after the roster dropped the agent", r.Status)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, err := w.keys.Local().Open(context.Background(), g.Subject.Kid, b.static.Public()); err == nil {
		t.Fatal("the key outlived its agent")
	}
}

// An agent past its end fails at the box, which refuses it whatever the
// cloud admits; and the cloud stops admitting it at the end the roster
// names, by its own clock, without waiting for a roster.
func TestAnExpiredAgentFails(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	if _, isErr, text := a.call("status", nil); isErr {
		t.Fatal(text)
	}
	b.expire(a.agentKey, time.Now().Add(-time.Second))
	if _, isErr, text := a.call("status", nil); !isErr || !strings.Contains(text, "ran out") {
		t.Fatalf("the box served an agent past its end: %v %s", isErr, text)
	}

	b2 := w.connectBox()
	a2 := w.connect(b2, "")
	until := time.Now().Add(600 * time.Millisecond)
	b2.approveUntil(a2.agentKey, a2.clientID, until, oauth.ReadScopes...)
	time.Sleep(50 * time.Millisecond)
	if _, isErr, text := a2.call("status", nil); isErr {
		t.Fatal(text)
	}
	time.Sleep(time.Until(until) + 50*time.Millisecond)
	if r := a2.rpc("tools/call", map[string]any{"name": "status"}, true); r.Status != http.StatusUnauthorized {
		t.Fatalf("an expired agent's call: %d", r.Status)
	}
	// And the door refuses its key, whatever token it brings.
	g := oauth.Subject{Kind: oauth.SubjectAgent, Home: b2.home, Agent: cloudwire.DeviceID(a2.agentKey), Key: a2.agentKey}
	w.pool.Drop(b2.home, g.Agent)
	if _, err := w.pool.get(context.Background(), g); err != errDenied {
		t.Fatalf("the door admitted an agent past its end: %v", err)
	}
}

// The transport, both eras.
func TestTheTransport(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	c := w.client()

	// No token: 401 with the way to the metadata.
	resp, _ := c.Post(w.srv.URL+Path, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	// GET and DELETE: no stream, no session.
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequest(m, w.srv.URL+Path, nil)
		req.Header.Set("Authorization", "Bearer "+a.token)
		resp, _ := c.Do(req)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d", m, resp.StatusCode)
		}
	}
	// A page on a plain-http origin.
	req, _ := http.NewRequest(http.MethodPost, w.srv.URL+Path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Origin", "http://evil.example")
	req.Header.Set("Authorization", "Bearer "+a.token)
	if resp, _ := c.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a bad origin: %d", resp.StatusCode)
	}

	// 2026-07-28: discover, and the header checks.
	r := a.rpc("server/discover", nil, true)
	res := r.Body["result"].(map[string]any)
	if r.Status != 200 || res["resultType"] != "complete" || res["supportedVersions"].([]any)[0] != Modern {
		t.Fatalf("server/discover: %v", r.Body)
	}
	if code := rpcCode(a.raw(map[string]string{"MCP-Protocol-Version": "2025-06-18", "Mcp-Method": "tools/list"}, "tools/list", Modern, nil)); code != codeHeaderMismatch {
		t.Fatalf("version header mismatch: %d", code)
	}
	if code := rpcCode(a.raw(map[string]string{"MCP-Protocol-Version": Modern, "Mcp-Method": "tools/call", "Mcp-Name": "plan.get"}, "tools/call", Modern, map[string]any{"name": "status"})); code != codeHeaderMismatch {
		t.Fatalf("name header mismatch: %d", code)
	}
	r2 := a.raw(map[string]string{"MCP-Protocol-Version": "1900-01-01", "Mcp-Method": "tools/list"}, "tools/list", "1900-01-01", nil)
	if r2.Status != 400 || rpcCode(r2) != codeUnsupportedVer {
		t.Fatalf("unsupported version: %d %v", r2.Status, r2.Body)
	}
	if r := a.rpc("resources/list", nil, true); r.Status != 404 || rpcCode(r) != codeMethodNotFound {
		t.Fatalf("an unknown method: %d %v", r.Status, r.Body)
	}
	// Base64 in Mcp-Name.
	r3 := a.raw(map[string]string{"MCP-Protocol-Version": Modern, "Mcp-Method": "tools/call", "Mcp-Name": "=?base64?c3RhdHVz?="}, "tools/call", Modern, map[string]any{"name": "status"})
	if r3.Status != 200 {
		t.Fatalf("a Base64 Mcp-Name: %d %v", r3.Status, r3.Body)
	}

	// The earlier revisions: initialize, the notification, then calls with
	// no _meta.
	r = a.rpc("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "old", "version": "1"}}, false)
	res = r.Body["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || r.Header.Get("Mcp-Session-Id") != "" {
		t.Fatalf("initialize: %v", r.Body)
	}
	note := a.notify("notifications/initialized")
	if note != http.StatusAccepted {
		t.Fatalf("notifications/initialized: %d", note)
	}
	r = a.rpc("tools/call", map[string]any{"name": "status"}, false)
	if r.Status != 200 || r.Body["result"].(map[string]any)["isError"] != false {
		t.Fatalf("legacy tools/call: %v", r.Body)
	}
	// Batches are gone.
	req, _ = http.NewRequest(http.MethodPost, w.srv.URL+Path, strings.NewReader(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`))
	req.Header.Set("Authorization", "Bearer "+a.token)
	if resp, _ := c.Do(req); resp.StatusCode != 400 {
		t.Fatalf("a batch: %d", resp.StatusCode)
	}
}

// raw posts with chosen headers.
func (a *assistant) raw(headers map[string]string, method, version string, params map[string]any) rpcReply {
	a.w.t.Helper()
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": version, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 9, "method": method, "params": params})
	req, _ := http.NewRequest(http.MethodPost, a.w.srv.URL+Path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+a.token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.w.client().Do(req)
	if err != nil {
		a.w.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := rpcReply{Status: resp.StatusCode, Header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&out.Body)
	return out
}

func (a *assistant) notify(method string) int {
	req, _ := http.NewRequest(http.MethodPost, a.w.srv.URL+Path, strings.NewReader(`{"jsonrpc":"2.0","method":"`+method+`"}`))
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.w.client().Do(req)
	if err != nil {
		a.w.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

func rpcCode(r rpcReply) int {
	e, _ := r.Body["error"].(map[string]any)
	if e == nil {
		return 0
	}
	n, _ := e["code"].(float64)
	return int(n)
}

// A tool whose scope the token lacks answers 403 insufficient_scope, so
// the client can ask the owner for more.
func TestStepUp(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, oauth.ScopeLiveRead, oauth.ScopeLiveRead)
	if a.scope != oauth.ScopeLiveRead {
		t.Fatalf("scope %q", a.scope)
	}
	r := a.rpc("tools/call", map[string]any{"name": "plan.get"}, true)
	h := r.Header.Get("WWW-Authenticate")
	if r.Status != 403 || !strings.Contains(h, `error="insufficient_scope"`) || !strings.Contains(h, `scope="`+oauth.ScopePlanRead+`"`) {
		t.Fatalf("step-up: %d %s", r.Status, h)
	}
	if _, _, p := b.counts(); len(p) != 0 {
		t.Fatalf("a call without its scope reached the box: %v", p)
	}
}

// Calls on one home queue for the session, a few at most, and the box never
// gets two at once.
func TestFanOutIsBounded(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	a.call("status", nil) // warm
	b.mu.Lock()
	b.delay = 150 * time.Millisecond
	b.mu.Unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	busy, ok := 0, 0
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, isErr, text := a.call("status", nil)
			mu.Lock()
			defer mu.Unlock()
			if isErr && strings.Contains(text, "busy") {
				busy++
			} else if !isErr {
				ok++
			}
		}()
	}
	wg.Wait()
	b.mu.Lock()
	most := b.maxFlight
	b.mu.Unlock()
	if most != 1 {
		t.Fatalf("the box had %d requests at once", most)
	}
	// How many get in depends on timing; that some are turned away, and
	// none are lost, does not.
	if busy == 0 || ok == 0 || ok+busy != 12 {
		t.Fatalf("%d answered, %d told busy", ok, busy)
	}
}

// A warm session is reused, and closes when idle: the box hears it end.
func TestTheWarmSessionClosesWhenIdle(t *testing.T) {
	w := newWorld(t, func(w *world) { w.pool.Idle = 200 * time.Millisecond })
	b := w.connectBox()
	a := w.connect(b, "")
	a.call("status", nil)
	a.call("status", nil)
	if w.pool.Warm() != 1 {
		t.Fatalf("%d warm sessions", w.pool.Warm())
	}
	w.pool.sweep() // too soon: still warm
	if w.pool.Warm() != 1 {
		t.Fatal("swept a busy session")
	}
	time.Sleep(300 * time.Millisecond)
	w.pool.sweep()
	if w.pool.Warm() != 0 {
		t.Fatal("an idle session stayed")
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, ends, _ := b.counts(); ends == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the box did not hear the session end")
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.call("status", nil)
	if h, _, _ := b.counts(); h != 2 {
		t.Fatalf("%d handshakes after an idle close", h)
	}
}

// A box that takes no agents yet says so in words.
func TestABoxWithoutAgentsSaysSo(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	w.mu.Lock()
	delete(w.boxes, b.home)
	w.mu.Unlock()
	if _, isErr, text := a.call("status", nil); !isErr || !strings.Contains(text, "newer FTW version") {
		t.Fatalf("%v %s", isErr, text)
	}
}

// The box's refusals reach the model as words, with the code.
func TestBoxRefusalsInWords(t *testing.T) {
	for code, want := range map[string]string{
		"E_SCOPE_DENIED":    "has not given this assistant",
		"E_OP_NOT_GRANTED":  "does not include this operation",
		"E_GRANT_EXPIRED":   "ran out",
		"E_NEEDS_OWNER":     "use goal.request",
		"E_RANGE_TOO_LARGE": "too large",
		"E_GRANT_REVOKED":   "removed this assistant",
		"E_BOOTING":         "starting up",
		"E_UNKNOWN_OP":      "newer FTW version",
		"E_WEIRD\u202e":     "refused this request",
	} {
		got := words(boxError{Code: code}).Error()
		if !strings.Contains(got, want) {
			t.Errorf("%s: %q", code, got)
		}
	}
	if got := words(boxError{Code: "E_UNAVAILABLE", Args: map[string]any{"reason": "busy"}}); got != errBusy {
		t.Errorf("busy: %v", got)
	}
}

func TestCapAndRateRefusalsSayTheNumbers(t *testing.T) {
	if got := words(boxError{Code: "E_CAP_EXCEEDED", Args: map[string]any{"cap": "maxW", "max": uint64(7400)}}).Error(); !strings.Contains(got, "maxW") || !strings.Contains(got, "7400") {
		t.Fatal(got)
	}
	if got := words(boxError{Code: "E_RATE_LIMITED", Args: map[string]any{"retryAfterMs": uint64(4000)}}).Error(); !strings.Contains(got, "4000") {
		t.Fatal(got)
	}
}
