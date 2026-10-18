package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw/go/protocol"
)

func apiTools() []*tool {
	return []*tool{
		{
			name: "api_catalog", title: "Diagnostic API reads",
			description: "List the diagnostic API reads this token may use, their scopes and query parameters. Includes the energy ledger, individual measured series, forecasts, learned models and planner snapshots. The catalogue describes the protocol; the box must support api.read to serve them." + dataNote,
			scope:       readScope(protocol.MsgAPIRead), input: object(nil), readOnly: true,
			run: func(_ context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				if err := decodeArgs(args, &struct{}{}); err != nil {
					return nil, err
				}
				routes := make([]protocol.AgentAPIRoute, 0, len(protocol.AgentAPIRoutes))
				for _, route := range protocol.AgentAPIRoutes {
					if cc.grant.Has(route.Scope) {
						routes = append(routes, route)
					}
				}
				return map[string]any{"catalogSource": "protocol", "routes": routes, "requiredScope": readScope(protocol.MsgAPIRead),
					"timeUnit": "Time query parameters accept Unix milliseconds or RFC 3339 with an explicit timezone", "maxBytes": protocol.AgentAPIMaxBytes}, nil
			},
		},
		{
			name: "api_read", title: "Read diagnostic API data",
			description: "Read one exact JSON path from api_catalog. The box checks the grant and redacts the answer. For energy evidence use /api/energy/assets and /api/energy/history: Wh, flow, source, quality, provenance and sample_count stay intact. For an incident use /api/mpc/diagnose/history then /api/mpc/diagnose/at with ts. Time parameters accept Unix milliseconds or RFC 3339 with an explicit timezone. For a driver's readings use /api/series/catalog then /api/series. Use opaque ids returned by these catalogues. Set a narrow time range or a small limit first; truncated answers are errors. This read cannot write settings or control equipment." + dataNote,
			scope:       readScope(protocol.MsgAPIRead), readOnly: true,
			input: object(map[string]any{
				"path":      map[string]any{"type": "string", "description": "Exact path from api_catalog"},
				"query":     map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Query parameters from api_catalog; all values are strings"},
				"max_bytes": integer("Maximum JSON response size; narrow the query if it does not fit", 4096, protocol.AgentAPIMaxBytes, 64<<10),
			}, "path"),
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				var a struct {
					Path     string            `json:"path"`
					Query    map[string]string `json:"query"`
					MaxBytes *int64            `json:"max_bytes"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				route, known := protocol.AgentAPIPath(a.Path)
				if !known {
					return nil, userError("Choose an exact read path from api_catalog.")
				}
				if !cc.grant.Has(route.Scope) {
					return nil, apiScopeError(route.Scope)
				}
				for name, value := range a.Query {
					if _, ok := route.Query[name]; !ok || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n") {
						return nil, userError("Use only the query parameters listed for this path in api_catalog.")
					}
					switch name {
					case "since", "until", "since_ms", "until_ms", "ts":
						ms, err := strconv.ParseInt(value, 10, 64)
						if err != nil {
							when, parseErr := time.Parse(time.RFC3339Nano, value)
							if parseErr != nil {
								return nil, userError("Time parameters must be Unix milliseconds or RFC 3339 with a timezone, such as 2026-10-18T15:00:00+02:00.")
							}
							ms = when.UnixMilli()
						}
						if ms < 0 {
							return nil, userError("Time parameters must be at or after the Unix epoch.")
						}
						a.Query[name] = strconv.FormatInt(ms, 10)
					}
				}
				limit := int64(64 << 10)
				if a.MaxBytes != nil {
					if *a.MaxBytes < 4096 || *a.MaxBytes > protocol.AgentAPIMaxBytes {
						return nil, userError("max_bytes must be between 4096 and 1048576.")
					}
					limit = *a.MaxBytes
				}
				conn, err := cc.conn(ctx)
				if err != nil {
					return nil, err
				}
				ctx, cancel := context.WithTimeout(ctx, cc.s.pool.Call)
				defer cancel()
				head, body, err := conn.apiRead(ctx, protocol.APIRead{Path: a.Path, Query: a.Query, MaxBytes: limit})
				if err != nil {
					var refusal boxError
					if errors.As(err, &refusal) && refusal.Code == protocol.ErrScopeDenied {
						return nil, userError("The box refused api.read (E_SCOPE_DENIED). Use health_get to check its Core version: it needs a release with diagnostic API reads. The box's grant must also include " + readScope(protocol.MsgAPIRead) + " and " + route.Scope + ".")
					}
					return nil, words(err)
				}
				var data any
				dec := json.NewDecoder(bytes.NewReader(body))
				dec.UseNumber()
				if !json.Valid(body) || dec.Decode(&data) != nil {
					return nil, userError("The box's diagnostic answer was not valid JSON.")
				}
				return map[string]any{"path": a.Path, "status": head.Status, "body": jsonable(data)}, nil
			},
		},
	}
}

type apiScopeError string

func (e apiScopeError) Error() string { return "diagnostic data needs scope " + string(e) }

// apiRead collects the bounded api.* stream. A missing head, a skipped
// sequence or a truncated end never becomes a successful partial answer.
func (c *agentConn) apiRead(ctx context.Context, q protocol.APIRead) (protocol.APIHeadMsg, []byte, error) {
	release, err := c.take(ctx)
	if err != nil {
		return protocol.APIHeadMsg{}, nil, err
	}
	defer release()
	id := c.newID()
	ch := c.register(id)
	defer c.unregister(id)
	if err := c.send(ctx, protocol.MsgAPIRead, &id, q); err != nil {
		return protocol.APIHeadMsg{}, nil, err
	}
	var head protocol.APIHeadMsg
	var body []byte
	var next uint32
	started := false
	bad := func() (protocol.APIHeadMsg, []byte, error) {
		c.close(errEnded)
		return protocol.APIHeadMsg{}, nil, userError("The box's diagnostic response stream was incomplete. Retry the read.")
	}
	for {
		select {
		case env := <-ch:
			switch env.T {
			case protocol.MsgAPIHead:
				if started || cbor.Unmarshal(env.B, &head) != nil || head.Status < 100 || head.Status > 599 {
					return bad()
				}
				started = true
			case protocol.MsgAPIChunk:
				var chunk protocol.APIChunk
				if !started || cbor.Unmarshal(env.B, &chunk) != nil || chunk.Seq != next || len(body)+len(chunk.Data) > int(q.MaxBytes) {
					return bad()
				}
				next++
				body = append(body, chunk.Data...)
			case protocol.MsgAPIEnd:
				var end protocol.APIEnd
				if !started || cbor.Unmarshal(env.B, &end) != nil || end.Bytes != int64(len(body)) || head.Len != nil && *head.Len != end.Bytes {
					return bad()
				}
				c.p.pace(c.home).spend(len(body), c.p.now())
				if end.Truncated {
					return head, nil, userError("The answer exceeded max_bytes. Narrow the time range, points or limit, or increase max_bytes. No partial data was returned.")
				}
				return head, body, nil
			case protocol.MsgError:
				return head, nil, decodeBoxError(env.B)
			default:
				return bad()
			}
		case <-c.done:
			return head, nil, c.closeErr
		case <-ctx.Done():
			c.close(errTimeout)
			return head, nil, errTimeout
		}
	}
}
