package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The live body a v0.145.2 box gave an assistant, with its source ids: the
// numbers that started this, decoded the way the status tool decodes them.
func liveFromBox(t *testing.T, l cloudwire.Live) map[string]any {
	t.Helper()
	b, err := cbor.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	v, err := decodeData(b)
	if err != nil {
		t.Fatal(err)
	}
	out, ok := namedLive(v).(map[string]any)
	if !ok {
		t.Fatalf("namedLive gave %T", out)
	}
	// What the model gets is JSON.
	j, _ := json.Marshal(out)
	var back map[string]any
	if err := json.Unmarshal(j, &back); err != nil {
		t.Fatal(err)
	}
	return back
}

func TestStatusNamesEveryFieldTheRegistryNames(t *testing.T) {
	got := liveFromBox(t, cloudwire.Live{
		Fields: map[string]int64{"1": 1, "2": 1345, "3": 0, "4": 0, "5": 237, "6": 1345,
			"10": 0, "11": 29, "12": 30, "13": 7, "14": 200},
		FieldSources: map[string][]string{"2": {"m"}, "3": {"pv"}, "4": {"bat"}, "5": {"bat"},
			"6": {"bat", "m", "pv"}, "11": {"m"}, "12": {"m"}, "13": {"m"}},
		Sources: map[string]cloudwire.Source{
			"m":   {Kind: "meter", State: protocol.SourceLive, StaleAfterMs: 10_000},
			"pv":  {Kind: "pv", State: protocol.SourceLagging, StaleAfterMs: 10_000},
			"bat": {Kind: "battery", State: protocol.SourceStale, StaleAfterMs: 10_000},
		},
		Ages:              map[string]int64{"m": 800, "pv": 14_000},
		DispatchBlockedBy: []string{},
	})
	want := map[string]struct {
		id    float64
		value float64
		unit  any
	}{
		"mode": {1, 1, nil}, "grid_w": {2, 1345, "W"}, "pv_w": {3, 0, "W"}, "battery_w": {4, 0, "W"},
		"battery_soc": {5, 237, "permille"}, "load_w": {6, 1345, "W"}, "ev_w": {10, 0, "W"},
		"grid_l1_da": {11, 29, "dA"}, "grid_l2_da": {12, 30, "dA"}, "grid_l3_da": {13, 7, "dA"},
		"grid_fuse_da": {14, 200, "dA"},
	}
	readings := got["readings"].(map[string]any)
	if len(readings) != len(want) {
		t.Fatalf("readings %v", readings)
	}
	for name, w := range want {
		r, ok := readings[name].(map[string]any)
		if !ok || r["fieldId"] != w.id || r["value"] != w.value || r["unit"] != w.unit {
			t.Fatalf("%s: %v, want %+v", name, r, w)
		}
	}
	if r := readings["battery_soc"].(map[string]any); r["percent"] != 23.7 {
		t.Fatalf("battery_soc percent %v", r)
	}
	if r := readings["grid_l1_da"].(map[string]any); r["amps"] != 2.9 {
		t.Fatalf("grid_l1_da amps %v", r)
	}
	if r := readings["mode"].(map[string]any); !strings.Contains(r["meaning"].(string), "index") || r["sources"] != nil {
		t.Fatalf("mode %v", r)
	}
	// Freshness follows the sources: the grid is its meter's.
	if r := readings["grid_w"].(map[string]any); r["state"] != "live" || r["ageMs"] != float64(800) {
		t.Fatalf("grid_w freshness %v", r)
	}
	// Load follows every flow, so it is as stale as the stalest, and the
	// stale battery has no age, so neither does load.
	if r := readings["load_w"].(map[string]any); r["state"] != "stale" || r["ageMs"] != nil {
		t.Fatalf("load_w freshness %v", r)
	}
	if r := readings["pv_w"].(map[string]any); r["state"] != "lagging" || r["ageMs"] != float64(14_000) {
		t.Fatalf("pv_w freshness %v", r)
	}
	// The fuse is config and the charger sum has no single source.
	for _, name := range []string{"grid_fuse_da", "ev_w"} {
		if r := readings[name].(map[string]any); r["sources"] != nil || r["state"] != nil {
			t.Fatalf("%s %v", name, r)
		}
	}
	// The box's own body is still there, by id, for anything that reads it.
	if f := got["fields"].(map[string]any); f["2"] != float64(1345) || len(f) != 11 {
		t.Fatalf("fields %v", f)
	}
	if fs := got["fieldSources"].(map[string]any); len(fs["6"].([]any)) != 3 {
		t.Fatalf("fieldSources %v", fs)
	}
	if got["unknownFields"] != nil || got["readingsNote"] == nil {
		t.Fatalf("envelope %v", got)
	}
}

func TestStatusNeverGuessesAFieldItHasNoNameFor(t *testing.T) {
	got := liveFromBox(t, cloudwire.Live{Fields: map[string]int64{"2": 10, "99": 5, "x": 1}, Ages: map[string]int64{}})
	if u := got["unknownFields"].(map[string]any); u["99"] != float64(5) || u["x"] != float64(1) || len(u) != 2 {
		t.Fatalf("unknownFields %v", got["unknownFields"])
	}
	readings := got["readings"].(map[string]any)
	if len(readings) != 1 || readings["grid_w"] == nil {
		t.Fatalf("readings %v", readings)
	}
	// A body without its source table has sources but no state to give.
}

func TestStatusWithoutTheSourceTableSaysItCannotTell(t *testing.T) {
	got := liveFromBox(t, cloudwire.Live{Fields: map[string]int64{"2": 10},
		FieldSources: map[string][]string{"2": {"m"}}, Ages: map[string]int64{"m": 5}})
	r := got["readings"].(map[string]any)["grid_w"].(map[string]any)
	if r["state"] != "unknown" || r["ageMs"] != float64(5) {
		t.Fatalf("grid_w %v", r)
	}
}

func TestStatusLeavesABodyWithoutFieldsAlone(t *testing.T) {
	in := map[string]any{"gridW": 1}
	if out := namedLive(in).(map[string]any); len(out) != 1 {
		t.Fatalf("changed %v", out)
	}
	if namedLive("text") != "text" {
		t.Fatal("changed a non-map")
	}
}
