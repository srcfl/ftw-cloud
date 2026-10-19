package mcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
)

// The control tools (docs/agents.md in srcfl/ftw, "Operations" and "Durable
// changes"). A hold is one cmd for an op the owner's grant lists, with the
// arguments the registry allows an agent and within the grant's caps
// (loadpoint.hold is the one hold op), and it always ends by itself: control ends when the assistant stops
// renewing, and this service never renews a hold on its own. A lasting
// change is an agent.request, which the box keeps until an owner confirms
// it with Face ID. The tools take typed arguments only, so no text a model
// read in a log can become an instruction to a home. The service checks the
// grant's ops and caps before the box does, and never loosens them.

const (
	cmdValidFor     = 30 * time.Second
	cmdAnswerWithin = 10 * time.Second
	// defaultHoldMinutes is a hold's length when the call names none,
	// shortened to the grant's holdS.
	defaultHoldMinutes = 15
	// cmdIDKept is how long a call's command id is kept for a retry. A
	// renewal minutes later is a new command.
	cmdIDKept = time.Minute
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

func controlTools() []*tool {
	return []*tool{
		{
			name: "ev_charge_now", title: "Charge the car now", destructive: true,
			description: "Charge the car at one charger now, at a fixed power, for a few minutes within the caps the owner granted (see homes_list), or release this assistant's own hold with stop. It ends by itself; call again to renew. An owner's own hold wins. For a car that must reach a charge level by a time, use car_goal_request.",
			scope:       oauth.ScopeDispatchHold,
			input: object(map[string]any{
				"loadpoint":  map[string]any{"type": "string", "pattern": idPattern.String(), "description": "The charger's id, from chargers_list"},
				"power_w":    map[string]any{"type": "integer", "minimum": 1, "maximum": protocol.MaxWMax, "description": "Charging power in watts, at most the grant's maxW. Needed unless stop"},
				"minutes":    integer("How long to charge, at most the grant's holdS", 1, protocol.HoldSMax/60, defaultHoldMinutes),
				"phase_mode": enum("Phases to charge on", "auto", "1p", "3p"),
				"stop":       map[string]any{"type": "boolean", "description": "Release this assistant's own hold instead"},
			}, "loadpoint"),
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				a := struct {
					Loadpoint string `json:"loadpoint"`
					PowerW    *int64 `json:"power_w"`
					Minutes   int64  `json:"minutes"`
					PhaseMode string `json:"phase_mode"`
					Stop      bool   `json:"stop"`
				}{}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				body := map[string]any{"id": a.Loadpoint}
				if a.Stop {
					if a.PowerW != nil || a.Minutes != 0 || a.PhaseMode != "" {
						return nil, userError("stop takes only the loadpoint.")
					}
					body["clear"] = true
				} else {
					// The box reads a missing power as 0, a pause: charging
					// needs a power.
					if a.PowerW == nil || *a.PowerW < 1 {
						return nil, userError("power_w is needed, at least 1 W, to charge; use stop to release the hold.")
					}
					// hold_s is never 0: on the box that is the operator's
					// hold with no end, which an agent may never send.
					minutes := a.Minutes
					if minutes == 0 {
						minutes = min(defaultHoldMinutes, int64(cc.grant.Caps.HoldS/60))
					}
					if minutes < 1 {
						return nil, userError("minutes must be at least 1.")
					}
					body["hold_s"] = minutes * 60
					body["power_w"] = *a.PowerW
					if a.PhaseMode != "" {
						body["phase_mode"] = a.PhaseMode
					}
				}
				if err := cc.withinGrant(protocol.OpLoadpointHold, body); err != nil {
					return nil, err
				}
				return cc.command(ctx, protocol.OpLoadpointHold, body)
			},
		},
		{
			name:  "goal_request",
			title: "Ask for a lasting change",
			description: "Ask the owner for a lasting change: the home's mode, the planning style, solar-only charging at a charger, or a correction of the car's charge level. " +
				"Nothing changes until an owner confirms it in Settings → Access on the local box or in the FTW app; requests_list shows how it ended. Put your reason, in your own words, in why.",
			scope: oauth.ScopeGoalsRequest,
			input: object(map[string]any{
				"kind":           enum("What to change", "mode", "planning", "surplus_only", "car_charge_level"),
				"mode":           map[string]any{"type": "string", "pattern": idPattern.String(), "description": "With kind mode: a mode's key, from status"},
				"safety_k":       map[string]any{"type": "number", "minimum": 0, "maximum": 2, "description": "With kind planning: how cautious the plan is"},
				"battery_export": enum("With kind planning: whether the battery may sell to the grid", "unknown", "not_allowed", "allowed"),
				"loadpoint":      map[string]any{"type": "string", "pattern": idPattern.String(), "description": "With surplus_only or car_charge_level: the charger's id, from chargers_list"},
				"on":             map[string]any{"type": "boolean", "description": "With surplus_only: charge from solar surplus only"},
				"percent":        map[string]any{"type": "integer", "minimum": 0, "maximum": 100, "description": "With car_charge_level: the car's charge now"},
				"why":            map[string]any{"type": "string", "maxLength": protocol.RequestWhyMax, "description": "Why you ask, shown to the owner as your words"},
			}, "kind", "why"),
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				a := struct {
					Kind          string   `json:"kind"`
					Mode          string   `json:"mode"`
					SafetyK       *float64 `json:"safety_k"`
					BatteryExport string   `json:"battery_export"`
					Loadpoint     string   `json:"loadpoint"`
					On            *bool    `json:"on"`
					Percent       *int     `json:"percent"`
					Why           string   `json:"why"`
				}{}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				if a.Why == "" || len(a.Why) > protocol.RequestWhyMax {
					return nil, userError(fmt.Sprintf("why must say, in at most %d bytes, why you ask.", protocol.RequestWhyMax))
				}
				only := func(ok bool, msg string) error {
					if !ok {
						return userError(msg)
					}
					return nil
				}
				var op string
				var body map[string]any
				var err error
				switch a.Kind {
				case "mode":
					op, body = protocol.OpSetMode, map[string]any{"mode": a.Mode}
					err = only(idPattern.MatchString(a.Mode) && a.SafetyK == nil && a.BatteryExport == "" && a.Loadpoint == "" && a.On == nil && a.Percent == nil,
						"kind mode takes mode, a mode's key, and nothing else.")
				case "planning":
					op, body = protocol.OpPlannerPrefsSet, map[string]any{}
					if a.SafetyK != nil {
						body["safety_k"] = *a.SafetyK
					}
					if a.BatteryExport != "" {
						body["battery_export"] = a.BatteryExport
					}
					err = only(len(body) > 0 && a.Mode == "" && a.Loadpoint == "" && a.On == nil && a.Percent == nil,
						"kind planning takes safety_k, battery_export or both, and nothing else.")
				case "surplus_only":
					op = protocol.OpLoadpointSurplusOnlySet
					err = only(idPattern.MatchString(a.Loadpoint) && a.On != nil && a.Mode == "" && a.SafetyK == nil && a.BatteryExport == "" && a.Percent == nil,
						"kind surplus_only takes loadpoint and on.")
					if err == nil {
						body = map[string]any{"id": a.Loadpoint, "surplus_only": *a.On}
					}
				case "car_charge_level":
					op = protocol.OpLoadpointSoCSet
					err = only(idPattern.MatchString(a.Loadpoint) && a.Percent != nil && *a.Percent >= 0 && *a.Percent <= 100 &&
						a.Mode == "" && a.SafetyK == nil && a.BatteryExport == "" && a.On == nil,
						"kind car_charge_level takes loadpoint and percent, from 0 to 100.")
					if err == nil {
						body = map[string]any{"id": a.Loadpoint, "soc": float64(*a.Percent) / 100}
					}
				default:
					err = userError("kind must be mode, planning, surplus_only or car_charge_level.")
				}
				if err != nil {
					return nil, err
				}
				if err := cc.withinGrant(op, body); err != nil {
					return nil, err
				}
				return cc.request(ctx, protocol.AgentRequest{Op: op, Args: body, Why: clean(a.Why)})
			},
		},
		carGoalTool(),
		{
			name: "requests_list", title: "My requests",
			description: "This assistant's own grant on the box and the lasting changes it asked for, with how each ended: pending, approved, declined or expired." + dataNote,
			input:       object(nil), readOnly: true,
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				if err := decodeArgs(args, &struct{}{}); err != nil {
					return nil, err
				}
				return cc.read(ctx, protocol.MsgAgentList, nil)
			},
		},
	}
}

// withinGrant checks an op and its arguments against the owner's grant
// and the registry before the box does: the op in the grant's allowlist,
// each argument one the registry lets an agent send (protocol.
// RegistryAgentArgs), of its kind and range, and within the grant's caps.
// The service may hold a call to the grant; it never loosens it.
func (cc *callCtx) withinGrant(op string, args map[string]any) error {
	g := cc.grant
	if !slices.Contains(g.Ops, op) {
		return userError(fmt.Sprintf("The owner's grant does not include %s. The owner can add it in Settings → Access on the local box or in the FTW app.", op))
	}
	spec, ok := protocol.RegistryAgentArgs[op]
	if !ok {
		return userError(op + " is not open to assistants.")
	}
	for name := range args {
		if !slices.ContainsFunc(spec, func(a protocol.AgentArg) bool { return a.Name == name }) {
			return userError(fmt.Sprintf("%s takes no %s.", op, name))
		}
	}
	for _, a := range spec {
		v, present := args[a.Name]
		if !present {
			if a.Required {
				return userError(fmt.Sprintf("%s needs %s (%s).", op, a.Name, strings.ToLower(a.Label)))
			}
			continue
		}
		if err := checkArg(a, v, g.Caps); err != nil {
			return err
		}
	}
	return nil
}

// checkArg holds one argument to its registry kind, range and cap.
func checkArg(a protocol.AgentArg, v any, caps protocol.Caps) error {
	bad := func(why string) error { return userError(fmt.Sprintf("%s %s.", a.Name, why)) }
	switch a.Kind {
	case "loadpoint", "mode", "car":
		if s, ok := v.(string); !ok || !idPattern.MatchString(s) {
			return bad("must be an id the box gave")
		}
		return nil
	case "enum":
		if s, ok := v.(string); !ok || !slices.Contains(a.Values, s) {
			return bad("must be one of " + strings.Join(a.Values, ", "))
		}
		return nil
	case "bool":
		if _, ok := v.(bool); !ok {
			return bad("must be true or false")
		}
		return nil
	}
	var n float64
	switch x := v.(type) {
	case int64:
		n = float64(x)
	case int:
		n = float64(x)
	case float64:
		n = x
	default:
		return bad("must be a number")
	}
	if a.Min != nil && n < *a.Min {
		return bad(fmt.Sprintf("must be at least %g", *a.Min))
	}
	if a.Max != nil && n > *a.Max {
		return bad(fmt.Sprintf("must be at most %g", *a.Max))
	}
	switch a.Cap {
	case "maxW":
		if n > float64(caps.MaxW) {
			return userError(fmt.Sprintf("That is more power than this assistant may set, %d W. Ask for less.", caps.MaxW))
		}
	case "holdS":
		if n > float64(caps.HoldS) {
			return userError(fmt.Sprintf("That is longer than this assistant may hold, %d minutes. Ask for less, and renew.", caps.HoldS/60))
		}
	}
	return nil
}

// request sends one agent.request and reports what the box said.
func (cc *callCtx) request(ctx context.Context, r protocol.AgentRequest) (any, error) {
	raw, err := cbor.Marshal(r.Args)
	if err != nil || len(raw) > protocol.RequestArgsMax {
		return nil, userError("The request's arguments are too large.")
	}
	ok, err := cc.read(ctx, protocol.MsgAgentRequest, r)
	if err != nil {
		return nil, err
	}
	return map[string]any{"request": ok, "waitsForOwner": true,
		"note": "Nothing changes until an owner confirms it in Settings → Access on the local box or in the FTW app. requests_list shows how it ended."}, nil
}

// command sends one cmd and waits for what the box did. The box checks it
// against the agent's grant and caps, in Core's order. The control
// revision comes from the chargers' answer, read first when this session
// has not seen it, so the first command does not spend the grant's rate on
// a conflict; a stale one is learnt from E_CONFLICT and tried once more. A
// client's retry of the same call within a minute reuses its command id,
// so the box acts once.
func (cc *callCtx) command(ctx context.Context, op string, args map[string]any) (any, error) {
	c, err := cc.conn(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cc.s.pool.Call)
	defer cancel()
	h, at, err := c.helloOK(ctx)
	if err != nil {
		return nil, words(err)
	}
	c.mu.Lock()
	known := c.rev != 0
	c.mu.Unlock()
	if !known && cc.grant.Has(protocol.RegistryReads[protocol.MsgLoadpointsGet]) {
		_, _ = cc.read(ctx, protocol.MsgLoadpointsGet, nil)
	}
	key := cc.idemKey(op, args)
	release, err := c.take(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	for try := 0; ; try++ {
		uptime := h.Clock.UptimeMs + time.Since(at).Milliseconds()
		c.mu.Lock()
		rev := c.rev
		c.mu.Unlock()
		id := uuidV7()
		if try == 0 {
			id = cc.s.cmdIDs.get(key, id, time.Now())
		}
		cmd := protocol.Cmd{CmdID: id, Op: op, Args: args, NotValidAfterMs: uptime + cmdValidFor.Milliseconds(),
			Expect: protocol.Expect{Rev: rev, Guards: []protocol.Guard{}}}
		res, ack, err := c.cmd(ctx, cmd)
		if errors.Is(err, errAnswerLost) {
			return lostReport(ack, uptime), nil
		}
		if err != nil {
			return nil, words(err)
		}
		if res != nil && res.Error != nil && res.Error.Code == protocol.ErrConflict && try == 0 {
			if actual, ok := revArg(res.Error.Args["actual"]); ok {
				c.mu.Lock()
				c.rev = actual
				c.mu.Unlock()
				cc.s.cmdIDs.forget(key)
				continue
			}
		}
		if res != nil && res.Error != nil {
			if res.Error.Code == protocol.ErrNotFound && args["clear"] == true {
				return nil, userError("There is no hold of this assistant's on that charger to stop (E_NOT_FOUND).")
			}
			return nil, userError(fmt.Sprintf("The box did not do it (%s). %s", codeText(res.Error.Code),
				words(boxError{Code: res.Error.Code, Args: res.Error.Args}).Error()))
		}
		return commandReport(res, ack, uptime), nil
	}
}

// idemKey names one call for its retries: the agent, the JSON-RPC id, the
// op and its arguments. Empty when the call has no id.
func (cc *callCtx) idemKey(op string, args map[string]any) string {
	if cc.rpcID == "" {
		return ""
	}
	raw, _ := json.Marshal(args) // map keys sorted
	return cc.grant.Subject.Home + "/" + cc.grant.Subject.Agent + "/" + cc.rpcID + "/" + op + "/" + string(raw)
}

// cmdIDs remembers each call's command id for a minute.
type cmdIDs struct {
	mu sync.Mutex
	m  map[string]cmdIDEntry
}

type cmdIDEntry struct {
	id string
	at time.Time
}

// get returns the id a call had within cmdIDKept, or records fresh for it.
func (k *cmdIDs) get(key, fresh string, now time.Time) string {
	if key == "" {
		return fresh
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.m == nil || len(k.m) >= 4096 {
		k.m = map[string]cmdIDEntry{}
	}
	if e, ok := k.m[key]; ok && now.Sub(e.at) < cmdIDKept {
		return e.id
	}
	k.m[key] = cmdIDEntry{id: fresh, at: now}
	return fresh
}

func (k *cmdIDs) forget(key string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
}

// errAnswerLost is a command the box was sent whose answer never came: the
// session ended, for a restart, a reconnect or the box, or the call ran out
// of time. The box may or may not have acted.
var errAnswerLost = errors.New("mcp: the command's answer was lost")

// cmd sends one command and collects its ack and result. Once it is sent, a
// session that ends or a call that runs out loses the answer, not the
// command: errAnswerLost.
func (c *agentConn) cmd(ctx context.Context, cmd protocol.Cmd) (*protocol.CmdResult, *protocol.CmdAck, error) {
	ch := make(chan appwire.Envelope, 8)
	id := c.newID()
	c.mu.Lock()
	c.byCmd[cmd.CmdID] = ch
	c.waiting[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.byCmd, cmd.CmdID)
		delete(c.waiting, id)
		c.mu.Unlock()
	}()
	if err := c.send(ctx, protocol.MsgCmd, &id, cmd); err != nil {
		return nil, nil, err
	}
	wait := time.NewTimer(cmdAnswerWithin)
	defer wait.Stop()
	var ack *protocol.CmdAck
	for {
		select {
		case env := <-ch:
			switch env.T {
			case protocol.MsgCmdAck:
				var a protocol.CmdAck
				if cbor.Unmarshal(env.B, &a) == nil {
					ack = &a
				}
			case protocol.MsgCmdResult:
				var r protocol.CmdResult
				if cbor.Unmarshal(env.B, &r) != nil {
					return nil, ack, errEnded
				}
				return &r, ack, nil
			case protocol.MsgError:
				return nil, ack, decodeBoxError(env.B)
			}
		case <-wait.C:
			// Heard, perhaps, but not confirmed: say so rather than guess.
			return nil, ack, nil
		case <-c.done:
			return nil, ack, errAnswerLost
		case <-ctx.Done():
			return nil, ack, errAnswerLost
		}
	}
}

// lostReport says a command's outcome is unknown, never that it failed: the
// box may have acted before its answer was lost.
func lostReport(ack *protocol.CmdAck, uptime int64) map[string]any {
	out := commandReport(nil, ack, uptime)
	out["state"] = "unknown"
	out["note"] = "Unknown, not failed: the connection to the box ended before it answered, so it may or may not " +
		"have acted. Check status (chargers_list) before trying again."
	if ack != nil {
		out["note"] = "Unknown, not failed: the box accepted the command, then the connection ended before it " +
			"confirmed the result. Check status (chargers_list) before trying again."
	}
	return out
}

// commandReport says what the box did, never more than it confirmed.
func commandReport(res *protocol.CmdResult, ack *protocol.CmdAck, uptime int64) map[string]any {
	out := map[string]any{}
	switch {
	case res != nil:
		out["state"] = clean(res.State)
		if res.Observed != nil {
			out["observed"] = map[string]any{"value": res.Observed.Value, "source": clean(res.Observed.Src)}
		}
	case ack != nil:
		out["state"] = "accepted"
		out["note"] = "The box accepted the request but has not confirmed the result yet."
	default:
		out["state"] = "unknown"
		out["note"] = "The box did not answer in time; it may or may not act."
	}
	if ack != nil && ack.ExpiresAtMs > 0 {
		out["endsInSeconds"] = max((ack.ExpiresAtMs-uptime)/1000, 0)
	}
	return out
}

func revArg(v any) (uint64, bool) {
	switch n := v.(type) {
	case uint64:
		return n, true
	case int64:
		return uint64(n), n >= 0
	case float64:
		return uint64(n), n >= 0
	}
	return 0, false
}

// uuidV7 is a command id: 48 bits of Unix milliseconds, then random bits,
// with the version and variant set (RFC 9562).
func uuidV7() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(time.Now().UnixMilli()))
	copy(b[:6], ms[2:])
	b[6] = 0x70 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
