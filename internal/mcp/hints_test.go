package mcp

import (
	"slices"
	"testing"
)

// hints is each tool's readOnlyHint, destructiveHint and openWorldHint,
// written out so a change to one is a reviewed change to this table. The
// reasons are in docs/public-plugin.md, "Tool annotations".
var hints = map[string][3]bool{
	"homes_list":              {true, false, false},
	"status":                  {true, false, false},
	"chargers_list":           {true, false, false},
	"cars_list":               {true, false, false},
	"plan_get":                {true, false, false},
	"plan_explain":            {true, false, false},
	"history_query":           {true, false, false},
	"health_get":              {true, false, false},
	"logs_tail":               {true, false, false},
	"drivers_status":          {true, false, false},
	"config_get":              {true, false, false},
	"measurement_diagnostics": {true, false, false},
	"api_catalog":             {true, false, false},
	"api_read":                {true, false, false},
	"requests_list":           {true, false, false},
	"ev_charge_now":           {false, true, false},
	"goal_request":            {false, true, false},
	"car_goal_request":        {false, true, false},
	"setup_begin":             {true, false, false},
	"setup_schema":            {true, false, false},
	"setup_status":            {true, false, false},
	"setup_discover":          {true, false, true},
	"setup_edit":              {false, true, false},
	"setup_reset":             {false, true, false},
	"setup_validate":          {false, true, false},
	"setup_test":              {false, true, true},
	"setup_connect":           {false, true, true},
	"setup_commit":            {false, true, false},
	"setup_restart":           {false, true, false},
}

// Every listed tool carries all three hints as booleans, and they are the
// ones in the table. A new tool fails here until it has a row.
func TestToolHintsMatchTheTable(t *testing.T) {
	_, _, a := withControl(t)
	for _, modern := range []bool{false, true} {
		r := a.rpc("tools/list", nil, modern)
		var names []string
		for _, x := range r.Body["result"].(map[string]any)["tools"].([]any) {
			tl := x.(map[string]any)
			name := tl["name"].(string)
			names = append(names, name)
			want, ok := hints[name]
			if !ok {
				t.Errorf("%s has no row in hints", name)
				continue
			}
			ann := tl["annotations"].(map[string]any)
			for i, key := range []string{"readOnlyHint", "destructiveHint", "openWorldHint"} {
				got, isBool := ann[key].(bool)
				if !isBool || got != want[i] {
					t.Errorf("%s %s = %v, want %v", name, key, ann[key], want[i])
				}
			}
			// A read-only tool changes nothing, so it destroys nothing.
			if ann["readOnlyHint"] == true && ann["destructiveHint"] == true {
				t.Errorf("%s is read-only and destructive", name)
			}
		}
		for name := range hints {
			if !slices.Contains(names, name) {
				t.Errorf("hints lists %s, which is not served", name)
			}
		}
	}
}
