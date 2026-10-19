package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/srcfl/ftw/go/protocol"
)

type setupToolDef struct {
	name, title, message, description string
	input                             map[string]any
	readOnly                          bool
}

func setupTools() []*tool {
	checks := map[string]any{
		"revision":      integer("Exact draft revision returned by setup_status or setup_edit", 1, 9007199254740991, 1),
		"base_revision": integer("Live settings revision on which the draft is based", 0, 9007199254740991, 0),
		"sha256":        map[string]any{"type": "string", "description": "Exact draft digest from the box"},
	}
	commit := map[string]any{}
	for key, value := range checks {
		commit[key] = value
	}
	commit["confirmed"] = map[string]any{"type": "boolean", "description": "True only after the user reviewed this exact checked draft, its changes and any restart, and confirmed saving it"}
	definitions := []setupToolDef{
		{"setup_begin", "Begin owner-approved system setup", protocol.MsgSetupStatus,
			"Use when the user asks to configure a new or existing box. Request the separate setup and diagnostic grant together, then read the box's current draft and guide. This read changes nothing and never resets existing work. If no box is connected, guide the owner through Start assistant setup on its local page and approve this connection there. Then read setup_schema and follow the returned guide.", object(nil), true},
		{"setup_schema", "Start or understand system setup", protocol.MsgSetupSchema,
			"Use only when the user wants to set up or change an installation. Read the complete configuration schema, driver catalogue and workflow from the connected box. Ordinary status/history/control need no setup interview.", object(nil), true},
		{"setup_status", "Resume system setup", protocol.MsgSetupStatus,
			"Read the current masked draft, revision, digest, validation, save receipt, box-generated next questions, forecast-prior accounting and live commissioning status. Ask only missing questions from guide, at most three at once. Optional unknowns do not block saving. A read does not discover equipment, change settings or command hardware. Resume after an interruption or a lost reply. Saved, applied, measuring and verified control are separate facts.", object(nil), true},
		{"setup_edit", "Save answers in a setup draft", protocol.MsgSetupEdit,
			"Edit the exact current draft revision with either a JSON merge patch or JSON Patch operations. Ask small groups of questions and accept unknown answers. Omitted fields and saved credentials remain on the box. A merge patch replaces entire arrays; use operations to add, replace or remove one list entry or field, even in a large installation. Read the exact current revision before using an array index. Editing a draft does not apply it. Use the schema and real driver metadata; never invent limits, measurements or supported fields.",
			object(map[string]any{"revision": integer("Current draft revision; zero only before the first edit", 0, 9007199254740991, 0), "patch": map[string]any{"type": "object", "description": "JSON merge patch using fields from setup_schema; omit when using operations"}, "operations": map[string]any{"type": "array", "description": "JSON Patch add/replace/remove operations with path and value; omit patch. For example replace /drivers/0/name. The exact revision protects list indexes.", "items": map[string]any{"type": "object", "properties": map[string]any{"op": enum("Operation", "add", "replace", "remove"), "path": map[string]any{"type": "string"}, "value": map[string]any{}}, "required": []string{"op", "path"}, "additionalProperties": false}}}, "revision"), false},
		{"setup_reset", "Start a new draft from current settings", protocol.MsgSetupReset,
			"Discard this unfinished draft only when the user asks, or start another after a completed save. Requires its exact current revision. Keeps all current settings and credentials; does not restart the box. Carry useful answers forward when resolving a conflict.", object(map[string]any{"revision": integer("Current draft revision", 0, 9007199254740991, 0)}, "revision"), false},
		{"setup_validate", "Check a setup draft", protocol.MsgSetupValidate,
			"Validate the exact current draft against Core's own checks. Core may normalize fields into a new draft revision and checksum; review that returned configuration, changes, warnings, assumptions and any required restart with the user. Confirm and commit only the returned revision and checksum. Validation does not prove a device connects, measures or obeys control.", object(checks, "revision", "base_revision", "sha256"), false},
		{"setup_commit", "Save the setup the user confirmed", protocol.MsgSetupCommit,
			"Save only the exact draft the user reviewed and confirmed after setup_validate. Requires the separately owner-approved setup grant. Uses the box's existing durable Settings save and apply path, with a receipt committed in the same transaction. Retry the same revision and digest after a lost reply; never guess whether a save failed. Report saved, applied, restart_required and hardware_verified separately. This tool does not command hardware or approve Cloud sharing.", object(commit, "revision", "base_revision", "sha256", "confirmed"), false},
		{"setup_restart", "Apply saved setup that needs a restart", protocol.MsgSetupRestart,
			"Use only for the exact saved setup receipt when restart_pending is true and the user confirms the brief interruption. The box rejects a different or superseded saved revision. A restart request is not proof of success: reconnect after the pause, read setup_status, and check fresh equipment readings. Retry the same receipt after a lost reply; do not create another draft merely because the connection paused.", object(map[string]any{"saved_revision": integer("Exact saved_revision from the commit receipt", 1, 9007199254740991, 1), "sha256": checks["sha256"], "confirmed": map[string]any{"type": "boolean", "description": "True only after the user confirms the restart and its brief interruption"}}, "saved_revision", "sha256", "confirmed"), false},
	}
	preparation := map[string]string{"setup_discover": "discover", "setup_test": "test", "setup_connect": "connect"}
	revision := integer("Exact current draft revision; zero before the first edit", 0, 9007199254740991, 0)
	confirmed := map[string]any{"type": "boolean", "description": "True only after the user agrees to this discovery, read-only connection test or vendor sign-in"}
	driver := map[string]any{"type": "string", "description": "Exact driver name in the current draft"}
	definitions = append(definitions,
		setupToolDef{
			"setup_discover", "Find equipment for setup", protocol.MsgSetupEdit,
			"Only after the user agrees: scan the connected box's local network and optionally fingerprint compatible devices. Bound to the current draft revision. Results are observations to review; this does not select equipment or apply configuration.",
			object(map[string]any{"revision": revision, "confirmed": confirmed, "fingerprint": map[string]any{"type": "boolean", "description": "Also run read-only device fingerprints"}}, "revision", "confirmed"), false},
		setupToolDef{
			"setup_test", "Test a draft equipment connection", protocol.MsgSetupEdit,
			"After the user agrees, briefly run the selected draft driver to read equipment. Uses this draft's credentials and keeps any token rotation in the draft. Device writes and control hooks are blocked; a driver that needs an undeclared authentication or subscription write may need attention. Connection and readings do not prove actuation. Read setup_status afterward because credential rotation can advance the draft revision.",
			object(map[string]any{"revision": revision, "driver": driver, "confirmed": confirmed}, "revision", "driver", "confirmed"), false},
		setupToolDef{
			"setup_connect", "Sign in to equipment during setup", protocol.MsgSetupEdit,
			"Start the box's supported vendor browser sign-in for a driver already in the draft. The owner opens the returned authorization URL; tokens return only to the exact draft, never chat or live settings. Currently the box supports MyUplink browser consent; other drivers use their catalogue fields. Leave the draft unchanged until sign-in finishes, then read setup_status. After a restart, expired sign-in or conflict, start sign-in again while retaining the draft.",
			object(map[string]any{"revision": revision, "driver": driver, "confirmed": confirmed, "redirect_uri": map[string]any{"type": "string", "description": "The box's browser callback address ending /api/oauth/myuplink/callback, matching the vendor registration; ask the owner for this address"}}, "revision", "driver", "confirmed", "redirect_uri"), false},
	)
	var result []*tool
	for _, d := range definitions {
		d := d
		scope := protocol.RegistryAgentCalls[d.message]
		if d.name == "setup_begin" {
			scope = protocol.ScopeSetupWrite
		}
		result = append(result, &tool{name: d.name, title: d.title, description: d.description + dataNote,
			scope: scope, input: d.input, readOnly: d.readOnly, destructive: d.message == protocol.MsgSetupCommit || d.message == protocol.MsgSetupRestart,
			run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
				if !json.Valid(args) || len(args) > protocol.SetupRequestBytes {
					return nil, userError("Keep each setup patch below 10 KiB and use successive draft revisions.")
				}
				if action := preparation[d.name]; action != "" {
					var fields map[string]json.RawMessage
					if json.Unmarshal(args, &fields) != nil || fields == nil {
						return nil, userError("Send one setup action.")
					}
					fields["action"], _ = json.Marshal(action)
					args, _ = json.Marshal(fields)
					if len(args) > protocol.SetupRequestBytes {
						return nil, userError("Setup action is too large.")
					}
				}
				conn, err := cc.conn(ctx)
				if err != nil {
					return nil, err
				}
				ctx, cancel := context.WithTimeout(ctx, protocol.AgentAPIReadTimeout)
				defer cancel()
				head, body, err := conn.apiStream(ctx, d.message, protocol.SetupCall{JSON: args})
				if err != nil {
					return setupReplyLost(d.message, d.readOnly, err)
				}
				var answer map[string]any
				dec := json.NewDecoder(bytes.NewReader(body))
				dec.UseNumber()
				if !json.Valid(body) || dec.Decode(&answer) != nil || answer == nil {
					return setupReplyLost(d.message, d.readOnly, errors.New("invalid setup answer"))
				}
				result := map[string]any{"status": head.Status, "response": answer}
				if head.Status >= 400 {
					return failedToolData{result}, nil
				}
				return result, nil
			},
		})
	}
	return result
}

func setupReplyLost(message string, readOnly bool, err error) (any, error) {
	var refused boxError
	if errors.As(err, &refused) {
		return nil, words(refused)
	}
	if readOnly {
		return nil, userError("The setup answer was incomplete. Read setup_status to resume; no complete answer was returned.")
	}
	return map[string]any{
		"state": "unknown", "operation": message,
		"note": "The connection ended before a complete setup answer arrived. The box may have acted. Reconnect and read setup_status, its draft revision and last_commit. Retry a save or restart only with the same exact revision and receipt after checking that status; do not reset the draft or assume the operation failed.",
	}, nil
}
