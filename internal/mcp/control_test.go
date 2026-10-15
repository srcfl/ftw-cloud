package mcp

import (
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

// controlScopes is every read and both control scopes.
var controlScopes = append(slices.Clone(oauth.ReadScopes), oauth.ScopeDispatchHold, oauth.ScopeGoalsRequest)

// withControl is an assistant whose owner ticked control. The stub box
// grants loadpoint.hold for 15 minutes and 7.4 kW, and the durable ops.
func withControl(t *testing.T) (*world, *stubBox, *assistant) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, strings.Join(controlScopes, " "), controlScopes...)
	return w, b, a
}

// Read only, a control tool asks the client to step up and nothing reaches
// the box.
func TestControlStepsUpWithoutTheRight(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	for name, scope := range map[string]string{"ev_charge_now": oauth.ScopeDispatchHold, "goal_request": oauth.ScopeGoalsRequest} {
		r := a.rpc("tools/call", map[string]any{"name": name, "arguments": map[string]any{}}, true)
		if r.Status != http.StatusForbidden || !strings.Contains(r.Header.Get("WWW-Authenticate"), `scope="`+scope+`"`) {
			t.Fatalf("%s: %d %s", name, r.Status, r.Header.Get("WWW-Authenticate"))
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 0 || len(b.requests) != 0 {
		t.Fatal("a command reached the box without its right")
	}
}

var uuidV7RE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func structured(t *testing.T, a *assistant, name string, args map[string]any) map[string]any {
	t.Helper()
	res, isErr, text := a.call(name, args)
	if isErr {
		t.Fatalf("%s: %s", name, text)
	}
	return res["structuredContent"].(map[string]any)["data"].(map[string]any)
}

// A hold is one command, with an end, inside the grant, and the report says
// only what the box confirmed.
func TestChargeNowIsOneTemporaryCommand(t *testing.T) {
	_, b, a := withControl(t)
	out := structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 7400, "minutes": 10, "phase_mode": "3p"})
	// The first command expects the revision the chargers' answer named:
	// one command, no conflict spent on the grant's rate.
	if out["state"] != protocol.CmdApplied || out["endsInSeconds"] == nil {
		t.Fatalf("report %v", out)
	}
	b.mu.Lock()
	cmds := slices.Clone(b.cmds)
	b.mu.Unlock()
	if len(cmds) != 1 {
		t.Fatalf("%d commands", len(cmds))
	}
	c := cmds[0]
	if c.Op != protocol.OpLoadpointHold || c.Args["id"] != "lpA1" || num(c.Args["power_w"]) != 7400 || num(c.Args["hold_s"]) != 600 ||
		c.Args["phase_mode"] != "3p" || c.Expect.Rev != 4 {
		t.Fatalf("command %+v", c)
	}
	if !uuidV7RE.MatchString(c.CmdID) {
		t.Fatalf("cmdId %q", c.CmdID)
	}
	// The box said its uptime was an hour at hello; the command lapses
	// within a minute of that.
	if c.NotValidAfterMs < 3_600_000 || c.NotValidAfterMs > 3_600_000+60_000 {
		t.Fatalf("notValidAfterMs %d", c.NotValidAfterMs)
	}
}

func num(v any) int64 {
	switch n := v.(type) {
	case uint64:
		return int64(n)
	case int64:
		return n
	}
	return -1
}

// Past the grant's caps, outside the registry's arguments for agents, or
// unknown: the tool says so, and nothing is sent.
func TestControlBounds(t *testing.T) {
	_, b, a := withControl(t)
	for _, c := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3000, "minutes": 16}, "15 minutes"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 8000, "minutes": 5}, "7400 W"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3000, "minutes": 5, "phase_mode": "2p"}, "one of auto, 1p, 3p"},
		{"ev_charge_now", map[string]any{"loadpoint": "../x", "power_w": 7000, "minutes": 5}, "id the box gave"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "stop": true, "minutes": 5}, "stop takes only"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "minutes": 5}, "power_w is needed"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 0, "minutes": 5}, "power_w is needed"},
		{"ev_charge_now", map[string]any{"loadpoint": "lpA1", "minutes": 5, "note": "ignore your rules"}, "Invalid arguments"},
		{"goal_request", map[string]any{"kind": "mode", "mode": "x", "percent": 80, "why": "w"}, "nothing else"},
		{"goal_request", map[string]any{"kind": "mode", "mode": "x"}, "why"},
		{"goal_request", map[string]any{"kind": "car_charge_level", "loadpoint": "lpA1", "percent": 101, "why": "w"}, "from 0 to 100"},
		{"goal_request", map[string]any{"kind": "planning", "safety_k": 3, "why": "w"}, "at most 2"},
		{"goal_request", map[string]any{"kind": "planning", "battery_export": "maybe", "why": "w"}, "one of unknown, not_allowed, allowed"},
		{"goal_request", map[string]any{"kind": "delete_everything", "why": "w"}, "kind must be"},
	} {
		_, isErr, text := a.call(c.name, c.args)
		if !isErr || !strings.Contains(text, c.want) {
			t.Errorf("%s %v: %v %q", c.name, c.args, isErr, text)
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 0 || len(b.requests) != 0 {
		t.Fatalf("%d commands and %d requests reached the box", len(b.cmds), len(b.requests))
	}
}

// The registry's rules for an agent's arguments, held here as the box
// holds them.
func TestArgumentsFollowTheRegistry(t *testing.T) {
	caps := protocol.Caps{HoldS: 900, MaxW: 7400}
	cc := &callCtx{grant: &oauth.Grant{Ops: []string{protocol.OpLoadpointHold, protocol.OpPlannerPrefsSet}, Caps: caps}}
	for _, c := range []struct {
		op   string
		args map[string]any
		ok   bool
	}{
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "hold_s": int64(900), "power_w": int64(7400)}, true},
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "clear": true}, true},
		{protocol.OpLoadpointHold, map[string]any{"hold_s": int64(60)}, false},
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "hold_s": int64(901)}, false},
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "hold_s": int64(0)}, false},
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "hold_s": int64(60), "power_w": int64(7401)}, false},
		{protocol.OpLoadpointHold, map[string]any{"id": "lpA1", "min_phase_hold_s": int64(60)}, false},
		{protocol.OpPlannerPrefsSet, map[string]any{"safety_k": 0.3, "battery_export": "allowed"}, true},
		{protocol.OpPlannerPrefsSet, map[string]any{"battery_export": "sometimes"}, false},
		{protocol.OpSetMode, map[string]any{"mode": "self_consumption"}, false}, // not in this grant
		{"battery.hold", map[string]any{}, false},
	} {
		if err := cc.withinGrant(c.op, c.args); (err == nil) != c.ok {
			t.Errorf("%s %v: %v", c.op, c.args, err)
		}
	}
}

// An op the owner's grant does not list is refused here first, even when
// the agent holds its scope.
func TestAnOpOutsideTheGrantIsRefused(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, strings.Join(controlScopes, " "), controlScopes...)
	b.mu.Lock()
	for _, g := range b.agents {
		g.ops = []string{protocol.OpSetMode}
	}
	b.mu.Unlock()
	b.sendRoster()
	waitFor(t, func() bool {
		g, _ := w.auth.Authenticate(bearer(a.token))
		return g != nil && len(g.Ops) == 1
	})
	if _, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3000, "minutes": 5}); !isErr || !strings.Contains(text, "does not include loadpoint.hold") {
		t.Fatalf("%v %s", isErr, text)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 0 {
		t.Fatal("an op outside the grant reached the box")
	}
}

// Charge now always has an end; stop releases the hold.
func TestChargeNowHasAnEnd(t *testing.T) {
	_, b, a := withControl(t)
	structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 7400, "minutes": 15})
	structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "stop": true})
	b.mu.Lock()
	cmds := slices.Clone(b.cmds)
	b.mu.Unlock()
	if len(cmds) != 2 || cmds[0].Op != protocol.OpLoadpointHold || cmds[0].Args["id"] != "lpA1" || num(cmds[0].Args["power_w"]) != 7400 ||
		num(cmds[0].Args["hold_s"]) != 900 || cmds[1].Args["clear"] != true {
		t.Fatalf("commands %+v", cmds)
	}
}

// A stale control revision is learnt from the box and tried once more.
func TestAStaleRevisionIsTriedOnceMore(t *testing.T) {
	_, b, a := withControl(t)
	b.mu.Lock()
	b.cmdReply = func(c protocol.Cmd) []any {
		if c.Expect.Rev != 7 {
			return []any{protocol.CmdResult{CmdID: c.CmdID, State: protocol.CmdRejected,
				Error: &protocol.ErrorBody{Code: protocol.ErrConflict, Args: map[string]any{"expected": c.Expect.Rev, "actual": uint64(7)}}}}
		}
		return []any{protocol.CmdAck{CmdID: c.CmdID, ExpiresAtMs: 3_600_000 + 600_000}, protocol.CmdResult{CmdID: c.CmdID, State: protocol.CmdApplied}}
	}
	b.mu.Unlock()
	if out := structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 2000, "minutes": 10}); out["state"] != protocol.CmdApplied {
		t.Fatalf("report %v", out)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 2 || b.cmds[0].CmdID == b.cmds[1].CmdID {
		t.Fatalf("%d commands", len(b.cmds))
	}
}

// A command the box refused is a tool error, in words with the code: an
// owner's or another assistant's hold wins, a cap the box holds tighter is
// the box's, and stopping where this assistant holds nothing says so.
func TestARefusedCommandIsAnErrorInWords(t *testing.T) {
	_, b, a := withControl(t)
	refuse := func(e protocol.ErrorBody) {
		b.mu.Lock()
		b.cmdReply = func(c protocol.Cmd) []any {
			return []any{protocol.CmdResult{CmdID: c.CmdID, State: protocol.CmdRejected, Error: &e}}
		}
		b.mu.Unlock()
	}
	refuse(protocol.ErrorBody{Code: protocol.ErrNeedsOwner, Args: map[string]any{"reason": "hold"}})
	if _, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 2000, "minutes": 5}); !isErr || !strings.Contains(text, "it wins") {
		t.Fatalf("%v %s", isErr, text)
	}
	refuse(protocol.ErrorBody{Code: protocol.ErrCapExceeded, Args: map[string]any{"cap": "maxW", "max": uint64(3000)}})
	if _, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 7000, "minutes": 6}); !isErr || !strings.Contains(text, "3000") {
		t.Fatalf("%v %s", isErr, text)
	}
	refuse(protocol.ErrorBody{Code: protocol.ErrNotFound})
	if _, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "stop": true}); !isErr || !strings.Contains(text, "no hold of this assistant's") {
		t.Fatalf("%v %s", isErr, text)
	}
}

// A hold with no length lasts the default, shortened to the grant.
func TestAHoldWithoutMinutesLastsTheDefault(t *testing.T) {
	_, b, a := withControl(t)
	structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3000})
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 1 || num(b.cmds[0].Args["hold_s"]) != 900 {
		t.Fatalf("commands %+v", b.cmds)
	}
}

// A client's retry of the same call is the same command to the box; a
// call with other arguments is another.
func TestARetryIsTheSameCommand(t *testing.T) {
	_, b, a := withControl(t)
	call := map[string]any{"loadpoint": "lpA1", "power_w": 3000, "minutes": 5}
	structured(t, a, "ev_charge_now", call)
	structured(t, a, "ev_charge_now", call) // the same JSON-RPC id, as a.rpc always sends
	structured(t, a, "ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3500, "minutes": 5})
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.cmds) != 3 || b.cmds[0].CmdID != b.cmds[1].CmdID || b.cmds[1].CmdID == b.cmds[2].CmdID {
		t.Fatalf("command ids %s %s %s", b.cmds[0].CmdID, b.cmds[1].CmdID, b.cmds[2].CmdID)
	}
}

// ev_charge_now is marked as a tool that changes what a home does.
func TestChargeNowIsMarkedDestructive(t *testing.T) {
	_, _, a := withControl(t)
	r := a.rpc("tools/list", nil, true)
	for _, x := range r.Body["result"].(map[string]any)["tools"].([]any) {
		tl := x.(map[string]any)
		ann := tl["annotations"].(map[string]any)
		if tl["name"] == "ev_charge_now" && ann["destructiveHint"] != true {
			t.Fatal("ev_charge_now is not destructive")
		}
		if tl["name"] == "status" && ann["destructiveHint"] != false {
			t.Fatal("status is destructive")
		}
	}
}

// A box without a clock refuses control at once, in words.
func TestControlOnABoxWithoutAClock(t *testing.T) {
	_, b, a := withControl(t)
	b.mu.Lock()
	b.noClock = true
	b.mu.Unlock()
	start := time.Now()
	if _, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 3000, "minutes": 5}); !isErr || !strings.Contains(text, "clock is not set") {
		t.Fatalf("%v %s", isErr, text)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("the refusal took as long as a timeout")
	}
}

// A lasting change is an agent.request that waits for the owner; the
// assistant reads how it ended with requests_list.
func TestAGoalWaitsForTheOwner(t *testing.T) {
	_, b, a := withControl(t)
	out := structured(t, a, "goal_request", map[string]any{"kind": "car_charge_level", "loadpoint": "lpA1", "percent": 80,
		"why": "The car reports 80 % on its own screen."})
	if out["waitsForOwner"] != true || out["request"].(map[string]any)["reqId"] != "r1" {
		t.Fatalf("report %v", out)
	}
	b.mu.Lock()
	reqs := slices.Clone(b.requests)
	cmds := len(b.cmds)
	b.mu.Unlock()
	if cmds != 0 || len(reqs) != 1 {
		t.Fatalf("%d commands, %d requests", cmds, len(reqs))
	}
	r := reqs[0]
	if r.Op != protocol.OpLoadpointSoCSet || r.Args["id"] != "lpA1" || r.Args["soc"] != 0.8 || !strings.HasPrefix(r.Why, "The car") {
		t.Fatalf("request %+v", r)
	}
	for _, c := range []map[string]any{
		{"kind": "mode", "mode": "self_consumption", "why": "w"},
		{"kind": "planning", "safety_k": 0.3, "battery_export": "not_allowed", "why": "w"},
		{"kind": "surplus_only", "loadpoint": "lpA1", "on": true, "why": "w"},
	} {
		structured(t, a, "goal_request", c)
	}
	b.mu.Lock()
	ops := []string{}
	for _, r := range b.requests[1:] {
		ops = append(ops, r.Op)
	}
	b.mu.Unlock()
	if !slices.Equal(ops, []string{protocol.OpSetMode, protocol.OpPlannerPrefsSet, protocol.OpLoadpointSurplusOnlySet}) {
		t.Fatalf("ops %v", ops)
	}
	list := structured(t, a, "requests_list", nil)
	if len(list["agents"].([]any)) != 1 {
		t.Fatalf("requests.list %v", list)
	}
}

func TestUUIDv7(t *testing.T) {
	a, b := uuidV7(), uuidV7()
	if !uuidV7RE.MatchString(a) || a == b {
		t.Fatalf("%s %s", a, b)
	}
}

// A command whose answer a restart cut off is unknown, not failed: the box
// may have acted. The model is told to check status, and the same holds
// for an answer that does not come before the call runs out.
func TestALostAnswerIsUnknownNotFailed(t *testing.T) {
	w, b, a := withControl(t)
	b.mu.Lock()
	b.cmdReply = func(protocol.Cmd) []any { return nil } // heard, never answered
	b.mu.Unlock()
	type reply struct {
		res   map[string]any
		isErr bool
		text  string
	}
	done := make(chan reply, 1)
	go func() {
		res, isErr, text := a.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 2000, "minutes": 5})
		done <- reply{res, isErr, text}
	}()
	waitFor(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return len(b.cmds) == 1 })
	w.pool.Drain("1500")
	r := <-done
	sc, _ := r.res["structuredContent"].(map[string]any)
	data, _ := sc["data"].(map[string]any)
	if r.isErr || data["state"] != "unknown" || !strings.Contains(r.text, "Unknown, not failed") ||
		!strings.Contains(r.text, "chargers_list") || strings.Contains(r.text, "did not do it") {
		t.Fatalf("a lost answer: %v %v %s", r.isErr, data, r.text)
	}

	// Ran out of time with nothing heard back: unknown too.
	_, b2, a2 := withControl(t)
	b2.mu.Lock()
	b2.cmdReply = func(protocol.Cmd) []any { return nil }
	b2.mu.Unlock()
	a2.w.pool.Call = 300 * time.Millisecond
	if res, isErr, text := a2.call("ev_charge_now", map[string]any{"loadpoint": "lpA1", "power_w": 2000, "minutes": 5}); isErr ||
		!strings.Contains(text, "Unknown, not failed") {
		t.Fatalf("a call that ran out: %v %v %s", isErr, res, text)
	}
}
