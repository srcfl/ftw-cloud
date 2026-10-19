package mcp

import (
	"context"
	"encoding/json"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

func carGoalTool() *tool {
	return &tool{
		name: "car_goal_request", title: "Ask for a car charging goal", scope: oauth.ScopeGoalsRequest,
		description: "Ask for a lasting car charging goal after the user confirms the car, target and departure time. Use the opaque car id from cars_list or charger_id from chargers_list, exactly one. Confirm the box time zone before converting local HH:MM into minutes after midnight. During setup, read runtime_timezone in setup_schema; otherwise use the known installation time zone or ask the owner to check it. Do not assume the assistant client time zone. days is a weekday mask: Monday=1 through Sunday=64; 0 means once at the next ready time, 127 means every day. A new goal replaces the previous schedule. Nothing changes until the owner approves in Settings → Access on the local box or in the FTW app. Read requests_list, then cars_list to check the outcome.",
		input: object(map[string]any{
			"car":             map[string]any{"type": "string", "description": "Opaque car id from cars_list"},
			"charger_id":      map[string]any{"type": "string", "description": "Opaque charger id, instead of car"},
			"percent":         map[string]any{"type": "integer", "minimum": 0, "maximum": 100, "description": "Target charge percent"},
			"ready_by_min":    map[string]any{"type": "integer", "minimum": 0, "maximum": 1439, "description": "Local departure time, minutes after midnight in the box time zone"},
			"days":            map[string]any{"type": "integer", "minimum": 0, "maximum": 127, "description": "Weekday mask: Monday=1 through Sunday=64; omitted or 0=once, 127=every day"},
			"finish_at_limit": map[string]any{"type": "boolean", "description": "Continue to the car's own charge limit"},
			"clear":           map[string]any{"type": "boolean", "description": "Remove the goal instead of setting a schedule"},
			"surplus_only":    map[string]any{"type": "boolean", "description": "Use solar surplus only"},
			"why":             map[string]any{"type": "string", "maxLength": protocol.RequestWhyMax},
		}, "why"),
		run: func(ctx context.Context, cc *callCtx, args json.RawMessage) (any, error) {
			var a struct {
				Car     string `json:"car"`
				Charger string `json:"charger_id"`
				Percent *int   `json:"percent"`
				Ready   *int   `json:"ready_by_min"`
				Days    *int   `json:"days"`
				Finish  *bool  `json:"finish_at_limit"`
				Clear   bool   `json:"clear"`
				Surplus *bool  `json:"surplus_only"`
				Why     string `json:"why"`
			}
			if err := decodeArgs(args, &a); err != nil {
				return nil, err
			}
			if (a.Car == "") == (a.Charger == "") || a.Why == "" || len(a.Why) > protocol.RequestWhyMax {
				return nil, userError("Send exactly one car or charger_id, and why.")
			}
			body := map[string]any{}
			if a.Car != "" {
				body["id"] = a.Car
			} else {
				body["charger_id"] = a.Charger
			}
			if a.Clear {
				if a.Percent != nil || a.Ready != nil || a.Days != nil || a.Finish != nil {
					return nil, userError("clear cannot include a schedule.")
				}
				body["clear"] = true
			} else if a.Percent != nil || a.Ready != nil || a.Days != nil || a.Finish != nil {
				if a.Percent == nil || a.Ready == nil {
					return nil, userError("A schedule needs percent and ready_by_min.")
				}
				body["target"] = float64(*a.Percent) / 100
				body["ready_by_min"] = *a.Ready
				if a.Days != nil {
					body["days"] = *a.Days
				}
				if a.Finish != nil {
					body["finish_at_limit"] = *a.Finish
				}
			} else if a.Surplus == nil {
				return nil, userError("Send a schedule, clear, or surplus_only.")
			}
			if a.Surplus != nil {
				body["surplus_only"] = *a.Surplus
			}
			if err := cc.withinGrant(protocol.OpCarGoalSet, body); err != nil {
				return nil, err
			}
			return cc.request(ctx, protocol.AgentRequest{Op: protocol.OpCarGoalSet, Args: body, Why: clean(a.Why)})
		},
	}
}
