package metrics

import (
	"errors"
	"testing"
	"time"
)

type hours struct{ got []Hour }

func (h *hours) PutHour(x Hour) error {
	h.got = append(h.got, x)
	return nil
}

func at(hh, mm int) time.Time { return time.Date(2026, 10, 24, hh, mm, 0, 0, time.UTC) }

// An hour holds each counter's rise, each gauge's low, high and mean over the
// minutes sampled, and each histogram's buckets; it goes to the store once
// the clock has left it, and Close hands over the one it is in.
func TestTheKeeperRollsTheSeriesUpIntoHours(t *testing.T) {
	s := &Set{}
	c := s.Counter("ftwcloud_drops_total", "", "reason", "x")
	g := s.Gauge("ftwcloud_sockets", "", "kind", "box")
	h := s.Histogram("ftwcloud_forward_seconds", "", "path", "tun_up")
	c.Add(7) // before this process's keeper: not in its hours
	g.Add(2)

	now := at(5, 10)
	store := &hours{}
	k := &Keeper{set: s, store: store, now: func() time.Time { return now }}
	k.begin()

	c.Add(3)
	now = at(5, 11)
	k.sample()
	g.Add(3)
	for range 10 {
		h.Observe(2 * time.Millisecond)
	}
	now = at(5, 12)
	k.sample()
	now = at(6, 0)
	k.sample()
	if len(store.got) != 1 {
		t.Fatalf("%d hours handed over", len(store.got))
	}
	five := store.got[0]
	if five.Start != at(5, 0).UnixMilli() || five.Ms != (50*time.Minute).Milliseconds() || five.Starts != 1 {
		t.Fatalf("hour %+v", five)
	}
	if five.Counters["drops_x"] != 3 {
		t.Fatalf("counters %v", five.Counters)
	}
	if g := five.Gauges["sockets_box"]; g != (GaugeHour{Min: 2, Max: 5, Sum: 9, N: 3}) {
		t.Fatalf("gauge %+v", g)
	}
	if b := five.Histograms["forward_seconds_tun_up"]; Quantile(b, 0.99) != 0.0025 || sum(b) != 10 {
		t.Fatalf("buckets %v", b)
	}

	c.Inc()
	now = at(6, 30)
	k.Close()
	k.sample()
	k.Close()
	if len(store.got) != 2 {
		t.Fatalf("%d hours handed over", len(store.got))
	}
	six := store.got[1]
	if six.Start != at(6, 0).UnixMilli() || six.Ms != (30*time.Minute).Milliseconds() || six.Starts != 0 ||
		six.Counters["drops_x"] != 1 || six.Gauges["sockets_box"] != (GaugeHour{Min: 5, Max: 5, Sum: 5, N: 1}) {
		t.Fatalf("hour %+v", six)
	}
}

// A restart inside an hour adds the new process's part to the old one's.
func TestARestartAddsToTheHourItSplit(t *testing.T) {
	a := newHour(at(5, 0))
	a.Ms, a.Starts = 40*60_000, 0
	a.Counters["tun_frames_up"] = 100
	a.Gauges["sockets_box"] = GaugeHour{Min: 90, Max: 100, Sum: 950, N: 10}
	a.Histograms["handshake_seconds_box"] = []int64{1, 2, 0}
	b := newHour(at(5, 0))
	b.Ms, b.Starts = 19*60_000, 1
	b.Counters["tun_frames_up"] = 40
	b.Counters["drains"] = 1
	b.Gauges["sockets_box"] = GaugeHour{Min: 0, Max: 99, Sum: 500, N: 10}
	b.Gauges["homes"] = GaugeHour{Min: 3, Max: 3, Sum: 3, N: 1}
	b.Histograms["handshake_seconds_box"] = []int64{0, 5, 1}
	a.Merge(b)
	if a.Ms != 59*60_000 || a.Starts != 1 || a.Counters["tun_frames_up"] != 140 || a.Counters["drains"] != 1 {
		t.Fatalf("%+v", a)
	}
	if a.Gauges["sockets_box"] != (GaugeHour{Min: 0, Max: 100, Sum: 1450, N: 20}) || a.Gauges["homes"].N != 1 {
		t.Fatalf("gauges %+v", a.Gauges)
	}
	if b := a.Histograms["handshake_seconds_box"]; b[0] != 1 || b[1] != 7 || b[2] != 1 {
		t.Fatalf("buckets %v", b)
	}
}

// An hour the store refuses is reported, and the keeper goes on.
func TestAnHourTheStoreRefusesIsReported(t *testing.T) {
	s := &Set{}
	var heard error
	now := at(5, 59)
	k := &Keeper{set: s, store: refusing{}, failed: func(err error) { heard = err }, now: func() time.Time { return now }}
	k.begin()
	now = at(6, 0)
	k.sample()
	if heard == nil {
		t.Fatal("the refusal went unheard")
	}
	if k.hour.Start != at(6, 0).UnixMilli() {
		t.Fatal("the keeper stopped at the refusal")
	}
}

type refusing struct{}

func (refusing) PutHour(Hour) error { return errors.New("disk full") }

func sum(b []int64) (n int64) {
	for _, c := range b {
		n += c
	}
	return n
}
