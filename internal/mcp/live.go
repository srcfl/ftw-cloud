package mcp

import (
	"strconv"

	"github.com/srcfl/ftw/go/protocol"
)

// The box's live body keys its readings by field id ("2" for the grid's
// power), which is right for a wire and wrong for a model: an assistant
// reading {"2": 1345} has to guess. namedLive keeps the box's body as it is,
// so nothing that reads fields, fieldSources or ages by id changes, and adds
// beside it each reading by the registry's name (srcfl/ftw
// contract/registry.yaml, through protocol.FieldNames and FieldUnits) with
// its unit, the sources it follows and how fresh they are. A field id the
// registry does not name is never given a guessed name: it goes, with its
// value, under unknownFields.

// liveNote tells a model how to read what namedLive adds.
const liveNote = "readings names each field by the FTW registry, with its unit, the opaque source ids it follows, " +
	"their worst state and the oldest of their ages in ms (null when no source has a current reading). " +
	"Power is in W, signed by FTW's site convention as the tool description says; a permille value also gives percent and a dA value also gives amps. " +
	"mode is the index of the box's operating mode in its own mode catalogue, not a mode name. " +
	"fields, fieldSources and ages are the box's own body, keyed by field id and source id. " +
	"unknownFields holds field ids this service has no name for."

// stateRank orders source states from best to worst. A state this service
// does not know ranks below never, so it can never read as live.
var stateRank = map[string]int{
	string(protocol.SourceLive): 0, string(protocol.SourceLagging): 1, string(protocol.SourceStale): 2,
	string(protocol.SourceDown): 3, string(protocol.SourceNever): 4,
}

// namedLive adds readings, unknownFields and a note to a live body. A body
// without a fields map is given back unchanged.
func namedLive(v any) any {
	body, ok := v.(map[string]any)
	if !ok {
		return v
	}
	fields, ok := body["fields"].(map[string]any)
	if !ok {
		return v
	}
	fieldSources, _ := body["fieldSources"].(map[string]any)
	sources, _ := body["sources"].(map[string]any)
	ages, _ := body["ages"].(map[string]any)

	readings := map[string]any{}
	unknown := map[string]any{}
	for key, val := range fields {
		id, err := strconv.ParseUint(key, 10, 32)
		name, known := protocol.FieldNames[protocol.Fid(id)]
		if err != nil || !known || name == "" {
			unknown[key] = val
			continue
		}
		r := map[string]any{"fieldId": id, "value": val}
		unit := protocol.FieldUnits[protocol.Fid(id)]
		if unit == "" {
			r["unit"] = nil
		} else {
			r["unit"] = unit
		}
		if n, ok := asNumber(val); ok {
			switch unit {
			case "permille":
				r["percent"] = n / 10
			case "dA":
				r["amps"] = n / 10
			}
		}
		if protocol.Fid(id) == protocol.FidMode {
			r["meaning"] = "index into the box's mode catalogue"
		}
		if ids := texts(fieldSources[key]); len(ids) > 0 {
			r["sources"] = ids
			r["state"], r["ageMs"] = freshness(ids, sources, ages)
		}
		readings[name] = r
	}
	body["readings"] = readings
	if len(unknown) > 0 {
		body["unknownFields"] = unknown
	}
	body["readingsNote"] = liveNote
	return body
}

// freshness is the worst state among a field's sources and the oldest of
// their ages: a reading is only as fresh as the stalest source it follows.
// The age is nil when any source has none, since the box sends an age only
// for a live or lagging source.
func freshness(ids []string, sources, ages map[string]any) (any, any) {
	worst, rank := "", -1
	var oldest int64
	aged := true
	for _, id := range ids {
		state := ""
		if s, ok := sources[id].(map[string]any); ok {
			state, _ = s["state"].(string)
		}
		r, ok := stateRank[state]
		if !ok {
			r, state = len(stateRank), "unknown"
		}
		if r > rank {
			worst, rank = state, r
		}
		a, ok := asInt(ages[id])
		if !ok {
			aged = false
			continue
		}
		oldest = max(oldest, a)
	}
	if sources == nil {
		// A live body carries its source table only when the table changed
		// and in every full message, so without one there is no state.
		worst = "unknown"
	}
	if !aged {
		return worst, nil
	}
	return worst, oldest
}

func asNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case uint64:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func texts(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
