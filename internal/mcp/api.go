package mcp

import (
	"bytes"
	"context"
	"encoding/hex"
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
			name: "api_catalog", title: "Start technical troubleshooting",
			description: "For technical troubleshooting, start here. Ask the connected box for every diagnostic read it supports, its running version, source-code links and a workflow for collecting bug-report evidence. Newer boxes include charger_connections with exact saved driver names and configured, missing or unverified_ocpp status; configured means a name matches, not verified equipment. Includes energy logs, original measurements, planner snapshots, configuration, driver source, logs, support reports and exports. The basic config_get and drivers_status tools redact names and cannot verify charger bindings. Ordinary status, history and control use the existing tools. The owner-approved diagnostic grant covers these reads; there are no extra endpoint permissions." + dataNote,
			scope:       readScope(protocol.MsgAPIRead), input: object(nil), readOnly: true,
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				if err := decodeArgs(args, &struct{}{}); err != nil {
					return nil, err
				}
				return diagnosticAPIRead(ctx, cc, protocol.APIRead{Path: protocol.AgentAPICatalogPath})
			},
		},
		{
			name: "api_read", title: "Read full technical diagnostic data",
			description: "Use during technical troubleshooting after api_catalog. Read any listed path, replacing {id} or {name} with the URL-encoded real value returned by the box. Technical names, addresses, exact numbers, source code and provenance stay intact. Use /api/support/report for an overview; /api/energy/history for Wh and provenance; /api/series for original measurements; /api/mpc/diagnose/history then /api/mpc/diagnose/at for incident planning. JSON, CSV, text and binary exports are supported. Large answers have byte pages: pass next_offset as offset and sha256 as if_sha256 to detect changed data. For ZIP or tar.gz exports, use archive_member '.' to list files, then a listed member name to read its contents as text. Binary pages use base64. Time parameters accept Unix milliseconds or RFC 3339 with a timezone. Reads use the existing handlers; controls and settings use their command tools." + dataNote,
			scope:       readScope(protocol.MsgAPIRead), readOnly: true,
			input: object(map[string]any{
				"path":           map[string]any{"type": "string", "description": "Path from api_catalog; URL-encode each path parameter"},
				"query":          map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "Existing API query parameters; all values are strings"},
				"max_bytes":      integer("Source bytes per page; larger answers return next_offset", 4096, protocol.AgentAPIPageBytes, 64<<10),
				"offset":         integer("Byte offset from next_offset", 0, 9007199254740991, 0),
				"archive_member": map[string]any{"type": "string", "description": "For ZIP or tar.gz: . lists files; a listed name reads that member"},
				"if_sha256":      map[string]any{"type": "string", "description": "SHA-256 from a prior page; refuses a changed answer"},
			}, "path"),
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				var a struct {
					Path          string            `json:"path"`
					Query         map[string]string `json:"query"`
					MaxBytes      *int64            `json:"max_bytes"`
					Offset        int64             `json:"offset"`
					IfSHA256      string            `json:"if_sha256"`
					ArchiveMember string            `json:"archive_member"`
				}
				if err := decodeArgs(args, &a); err != nil {
					return nil, err
				}
				if !protocol.ValidAgentAPIPath(a.Path) {
					return nil, userError("Choose a path from api_catalog without a query string or fragment. URL-encode each path parameter.")
				}
				if a.Offset < 0 {
					return nil, userError("offset must be zero or a next_offset returned by the box.")
				}
				if a.IfSHA256 != "" {
					b, err := hex.DecodeString(a.IfSHA256)
					if err != nil || len(b) != 32 {
						return nil, userError("if_sha256 must be the SHA-256 returned by the box.")
					}
				}
				for name, value := range a.Query {
					if name == "" || len(name) > 256 || len(value) > 2048 || strings.ContainsAny(name+value, "\x00\r\n") {
						return nil, userError("Invalid query parameter.")
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
					if *a.MaxBytes < 4096 || *a.MaxBytes > protocol.AgentAPIPageBytes {
						return nil, userError("max_bytes must be between 4096 and 131072 per page.")
					}
					limit = *a.MaxBytes
				}
				return diagnosticAPIRead(ctx, cc, protocol.APIRead{Path: a.Path, Query: a.Query, MaxBytes: limit, Offset: a.Offset, IfSHA256: a.IfSHA256, ArchiveMember: a.ArchiveMember})
			},
		},
	}
}

func diagnosticAPIRead(ctx context.Context, cc *callCtx, read protocol.APIRead) (any, error) {
	conn, err := cc.conn(ctx)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, protocol.AgentAPIReadTimeout)
	defer cancel()
	head, body, err := conn.apiRead(ctx, read)
	if err != nil {
		var refusal boxError
		if errors.As(err, &refusal) && refusal.Code == protocol.ErrScopeDenied {
			return nil, userError("The box refused api.read (E_SCOPE_DENIED). Use health_get to check its Core version: it needs a release with full diagnostic API reads, and its grant must include " + readScope(protocol.MsgAPIRead) + ".")
		}
		return nil, words(err)
	}
	var data map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if !json.Valid(body) || dec.Decode(&data) != nil || data == nil {
		return nil, userError("The box's diagnostic answer was not a JSON object.")
	}
	// Preserve the box's technical evidence, including exact json.Number
	// values. Existing typed reads retain their own display sanitization.
	result := map[string]any{"path": read.Path, "status": head.Status, "response": data}
	if head.Status >= 400 {
		return failedToolData{result}, nil
	}
	return result, nil
}

// apiRead collects the bounded api.* stream. A missing head, a skipped
// sequence or a truncated end never becomes a successful partial answer.
func (c *agentConn) apiRead(ctx context.Context, q protocol.APIRead) (protocol.APIHeadMsg, []byte, error) {
	return c.apiStream(ctx, protocol.MsgAPIRead, q)
}

func (c *agentConn) apiStream(ctx context.Context, message string, bodyValue any) (protocol.APIHeadMsg, []byte, error) {
	release, err := c.take(ctx)
	if err != nil {
		return protocol.APIHeadMsg{}, nil, err
	}
	defer release()
	id := c.newID()
	ch := c.register(id)
	defer c.unregister(id)
	if err := c.send(ctx, message, &id, bodyValue); err != nil {
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
				if !started || cbor.Unmarshal(env.B, &chunk) != nil || chunk.Seq != next || len(body)+len(chunk.Data) > protocol.AgentAPIMaxBytes {
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
					return head, nil, userError("The diagnostic wire answer was truncated. Reduce max_bytes or narrow the query and retry. No partial data was returned.")
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
