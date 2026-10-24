package metrics

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Hour is one clock hour of the service, for the operator to keep: how much
// each counter rose, each gauge's low, high and mean over the minutes
// sampled, and each histogram's buckets. Like every series it sums over the
// whole process: no home, device or address. Keys are the names of the
// minute's log line (Summarise).
type Hour struct {
	// Start is the hour, in Unix milliseconds, UTC.
	Start int64 `json:"start_ms"`
	// Ms is how much of the hour a process sampled. Less than an hour
	// means the hour held a start, a stop or a crash.
	Ms int64 `json:"ms"`
	// Starts is how many processes started in the hour: deploys and crashes.
	Starts     int64                `json:"starts"`
	Counters   map[string]int64     `json:"counters"`
	Gauges     map[string]GaugeHour `json:"gauges"`
	Histograms map[string][]int64   `json:"histograms"`
}

// GaugeHour is a gauge over an hour: its low, its high, and the sum and
// number of its samples.
type GaugeHour struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
	Sum int64 `json:"sum"`
	N   int64 `json:"n"`
}

func newHour(t time.Time) Hour {
	return Hour{Start: t.UTC().Truncate(time.Hour).UnixMilli(), Counters: map[string]int64{},
		Gauges: map[string]GaugeHour{}, Histograms: map[string][]int64{}}
}

// Merge adds o, a later part of the same hour, as when a process restarts
// inside it.
func (h *Hour) Merge(o Hour) {
	h.Ms += o.Ms
	h.Starts += o.Starts
	for k, v := range o.Counters {
		h.Counters[k] += v
	}
	for k, g := range o.Gauges {
		h.Gauges[k] = h.Gauges[k].merge(g)
	}
	for k, b := range o.Histograms {
		old := h.Histograms[k]
		if len(old) != len(b) {
			// The buckets changed between versions: the later ones win.
			h.Histograms[k] = slices.Clone(b)
			continue
		}
		for i := range b {
			old[i] += b[i]
		}
	}
}

func (g GaugeHour) merge(o GaugeHour) GaugeHour {
	if g.N == 0 {
		return o
	}
	if o.N == 0 {
		return g
	}
	return GaugeHour{Min: min(g.Min, o.Min), Max: max(g.Max, o.Max), Sum: g.Sum + o.Sum, N: g.N + o.N}
}

func (g GaugeHour) add(v int64) GaugeHour { return g.merge(GaugeHour{Min: v, Max: v, Sum: v, N: 1}) }

// Quantile is the upper bound, in seconds, of the LatencyBounds bucket that
// holds the q-th quantile of counts, +Inf past the last bound, or 0 without
// any.
func Quantile(counts []int64, q float64) float64 { return quantile(LatencyBounds, counts, q) }

// HourStore keeps hours. PutHour merges h into the hour already kept for
// h.Start, if there is one.
type HourStore interface {
	PutHour(h Hour) error
}

// Keeper rolls the series up into hours and hands each to a store when it
// ends. Run samples it on each whole minute; Close hands over the hour it is
// in, which a deploy calls after the drain so the drain's counts are in it.
type Keeper struct {
	set    *Set
	store  HourStore
	failed func(error)
	now    func() time.Time

	mu     sync.Mutex
	last   state
	at     time.Time
	hour   Hour
	closed bool
}

// NewKeeper starts the hour now, counting this process's start in it.
// failed hears each hour the store would not take, which is then lost.
func (s *Set) NewKeeper(store HourStore, failed func(error)) *Keeper {
	k := &Keeper{set: s, store: store, failed: failed, now: time.Now}
	k.begin()
	return k
}

func (k *Keeper) begin() {
	k.at = k.now()
	k.last = k.set.state()
	k.hour = newHour(k.at)
	k.hour.Starts = 1
	k.gauges(k.last)
}

// Run samples on each whole minute until ctx ends. The minute stays the
// unit after a slow tick, so no interval crosses an hour's end.
func (k *Keeper) Run(ctx context.Context) {
	for {
		now := k.now()
		t := time.NewTimer(now.Truncate(time.Minute).Add(time.Minute).Sub(now))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			k.sample()
		}
	}
}

// sample adds the time since the last sample to the hour it began in, and
// hands that hour over once the clock has left it.
func (k *Keeper) sample() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	now, cur := k.now(), k.set.state()
	k.rise(cur, now)
	if start := now.UTC().Truncate(time.Hour).UnixMilli(); start != k.hour.Start {
		k.put(k.hour)
		k.hour = newHour(now)
	}
	k.gauges(cur)
}

// Close hands over the hour so far and stops the keeper.
func (k *Keeper) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return
	}
	k.closed = true
	k.rise(k.set.state(), k.now())
	k.put(k.hour)
}

// rise adds each counter's and histogram's rise since the last sample.
func (k *Keeper) rise(cur state, now time.Time) {
	k.hour.Ms += max(0, now.Sub(k.at).Milliseconds())
	for x, v := range cur {
		before := k.last[x]
		switch x.kind {
		case counter:
			var prev int64
			if len(before) == 1 {
				prev = before[0]
			}
			k.hour.Counters[field(x)] += v[0] - prev
		case histogram:
			b := k.hour.Histograms[field(x)]
			if len(b) != len(v) {
				b = make([]int64, len(v))
			}
			for i := range v {
				b[i] += v[i]
				if i < len(before) {
					b[i] -= before[i]
				}
			}
			k.hour.Histograms[field(x)] = b
		}
	}
	k.last, k.at = cur, now
}

func (k *Keeper) gauges(cur state) {
	for x, v := range cur {
		if x.kind == gauge {
			k.hour.Gauges[field(x)] = k.hour.Gauges[field(x)].add(v[0])
		}
	}
}

func (k *Keeper) put(h Hour) {
	if err := k.store.PutHour(h); err != nil && k.failed != nil {
		k.failed(err)
	}
}
