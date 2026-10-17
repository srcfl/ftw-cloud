package mcp

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

// tile packs one box tile the way protocol.PackTile lays it out: one block of
// int32 per series, at the tile's stride.
func tile(res protocol.Resolution, stride, startMs int64, series []string, value func(name string, atMs int64) (int32, bool)) protocol.HistChunk {
	step := protocol.ResolutionStepMs[res] * stride
	points := protocol.PointsPerTile(res) / stride
	var data []byte
	for _, name := range series {
		for j := range points {
			v, ok := value(name, startMs+j*step)
			if !ok {
				v = math.MinInt32
			}
			data = binary.LittleEndian.AppendUint32(data, uint32(v))
		}
	}
	return protocol.HistChunk{Res: res, StartMs: startMs, StepMs: step, Series: series, Data: data}
}

// What the box answered a day at 24 points before: the hourly store, at a
// stride of 7, over the whole week-long tile, future included. What the
// tool now asks is every stored point of the day's tiles, which the box
// serves at its 5-minute store.
func TestHistoryAsksForEveryStoredPointOfTheRangesTiles(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 3, 0, 0, time.UTC).UnixMilli()
	from := now - 24*3_600_000
	// Three 12-hour tiles hold a day that does not start on a tile edge.
	if got := tilePoints(protocol.ResN5m, from, now); got != 3*144 {
		t.Fatalf("a day asks for %d points", got)
	}
	if got := tilePoints(protocol.ResN1h, now-30*24*3_600_000, now); got > 2000 || got < 30*24 {
		t.Fatalf("30 days ask for %d points", got)
	}
}

func TestHistoryKeepsToTheRangeAndAveragesToThePointsAskedFor(t *testing.T) {
	now := time.Date(2026, 10, 17, 6, 3, 0, 0, time.UTC).UnixMilli()
	from := now - 24*3_600_000
	series := []string{"grid_w", "pv_w"}
	var chunks []protocol.HistChunk
	for start := protocol.TileStartFor(protocol.ResN5m, from); start < now; start += protocol.ResolutionTileSpanMs[protocol.ResN5m] {
		chunks = append(chunks, tile(protocol.ResN5m, 1, start, series, func(name string, at int64) (int32, bool) {
			if at >= now {
				return 0, false // the future
			}
			if name == "pv_w" {
				return -2229, true // producing, by the site convention
			}
			// The hour's index, so each point's mean is its own hour.
			return int32((at - from) / 3_600_000), true
		}))
	}
	got := historyData(chunks, protocol.HistEnd{ResActual: protocol.ResN5m, Gaps: []protocol.HistGap{}}, from, now, 24)
	grid := got["series"].(map[string]any)["grid_w"].([]map[string]any)
	if len(grid) != 24 || got["stepS"] != int64(3600) {
		t.Fatalf("%d points at %v s", len(grid), got["stepS"])
	}
	first, _ := time.Parse(time.RFC3339, grid[0]["at"].(string))
	last, _ := time.Parse(time.RFC3339, grid[23]["at"].(string))
	if first.UnixMilli() < from-60_000 || last.UnixMilli() >= now {
		t.Fatalf("points from %v to %v for %v to %v", first, last, time.UnixMilli(from), time.UnixMilli(now))
	}
	for i, p := range grid {
		if p["w"] != int64(i) {
			t.Fatalf("point %d is %v", i, p["w"])
		}
	}
	if pv := got["series"].(map[string]any)["pv_w"].([]map[string]any); pv[5]["w"] != int64(-2229) {
		t.Fatalf("pv_w %v", pv[5])
	}
}

func TestHistoryLeavesAStepWithoutReadingsNull(t *testing.T) {
	from := int64(1_800_000_000_000)
	from -= from % 43_200_000
	to := from + 3_600_000
	ck := tile(protocol.ResN5m, 1, from, []string{"grid_w"}, func(_ string, at int64) (int32, bool) {
		return 50, at < from+1_800_000
	})
	got := historyData([]protocol.HistChunk{ck}, protocol.HistEnd{ResActual: protocol.ResN5m}, from, to, 12)
	grid := got["series"].(map[string]any)["grid_w"].([]map[string]any)
	if len(grid) != 12 || grid[0]["w"] != int64(50) || grid[5]["w"] != int64(50) || grid[6]["w"] != nil {
		t.Fatalf("grid %v", grid)
	}
}

// FTW lists events.get and diag.run and does not serve them yet. Its box
// says so with E_UNKNOWN_OP and the message type; the model is told that,
// and what to read instead, not to look for a newer FTW that does not exist.
func TestAnUnbuiltReadSaysSoAndWhatToUseInstead(t *testing.T) {
	for _, c := range []struct{ t, want string }{
		{protocol.MsgEventsGet, "logs_tail"},
		{protocol.MsgDiagRun, "drivers_status"},
	} {
		err := words(boxError{Code: protocol.ErrUnknownOp, Args: map[string]any{"t": c.t}})
		if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "E_UNKNOWN_OP") || strings.Contains(err.Error(), "newer FTW") {
			t.Fatalf("%s: %v", c.t, err)
		}
	}
	err := words(boxError{Code: protocol.ErrUnknownOp, Args: map[string]any{"t": "some.new"}})
	if !strings.Contains(err.Error(), "newer FTW") {
		t.Fatalf("an unknown read: %v", err)
	}
}
