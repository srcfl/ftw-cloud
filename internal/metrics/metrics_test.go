package metrics

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTheTextFormatHasEverySeries(t *testing.T) {
	s := &Set{}
	s.Counter("ftwcloud_drops_total", "Drops.", "reason", "tun_rate").Add(3)
	s.Counter("ftwcloud_drops_total", "Drops.", "reason", "slow_phone").Inc()
	s.Gauge("ftwcloud_sockets", "Sockets.", "kind", "box").Add(2)
	s.GaugeFunc("ftwcloud_homes", "Homes.", func() int64 { return 7 })
	h := s.Histogram("ftwcloud_forward_seconds", "Forward.", "path", "tun_down")
	h.Observe(300 * time.Microsecond)
	h.Observe(20 * time.Second)
	var b strings.Builder
	if _, err := s.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# TYPE ftwcloud_drops_total counter\n",
		`ftwcloud_drops_total{reason="tun_rate"} 3`,
		`ftwcloud_drops_total{reason="slow_phone"} 1`,
		`ftwcloud_sockets{kind="box"} 2`,
		"ftwcloud_homes 7",
		`ftwcloud_forward_seconds_bucket{path="tun_down",le="0.00025"} 0`,
		`ftwcloud_forward_seconds_bucket{path="tun_down",le="0.0005"} 1`,
		`ftwcloud_forward_seconds_bucket{path="tun_down",le="+Inf"} 2`,
		`ftwcloud_forward_seconds_count{path="tun_down"} 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Count(out, "# TYPE ftwcloud_drops_total") != 1 {
		t.Error("one name, one TYPE line")
	}
}

func TestTheLogLineCountsTheMinute(t *testing.T) {
	s := &Set{}
	c := s.Counter("ftwcloud_tun_frames_total", "Frames.", "dir", "up")
	h := s.Histogram("ftwcloud_forward_seconds", "Forward.", "path", "tun_up")
	c.Add(10)
	h.Observe(time.Millisecond)
	before := s.state()
	c.Add(5)
	for range 98 {
		h.Observe(400 * time.Microsecond)
	}
	h.Observe(40 * time.Millisecond)
	h.Observe(40 * time.Millisecond)
	line, err := s.line(before, s.state(), "s1", time.UnixMilli(1_792_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(line, &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]float64{
		"tun_frames_up":              5,
		"forward_seconds_tun_up_n":   100,
		"forward_seconds_tun_up_p50": 0.5,
		"forward_seconds_tun_up_p99": 50,
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v (line %s)", k, got[k], want, line)
		}
	}
	if got["Shard"] != "s1" || got["_aws"] == nil {
		t.Errorf("line %s", line)
	}
	if strings.Contains(string(line), "home") {
		t.Error("the line names a home")
	}
}
