// Package metrics counts what the service does, for its operator: sockets,
// homes, tunnel frames, drops, queue depths, Apple's answers and latencies.
// Nothing here names a home, a device or an address; every series is a sum
// over the whole process.
//
// The counts are served in Prometheus' text format on a loopback listener
// (ftwcloudd -metrics-listen) and summed once a minute into one log line
// (Logger). Each package keeps its own series as package variables on
// Default, so counting costs one atomic add and no wiring.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	runtimemetrics "runtime/metrics"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter only goes up.
type Counter struct{ v atomic.Int64 }

// Inc adds one.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n.
func (c *Counter) Add(n int64) { c.v.Add(n) }

// Load is the count so far.
func (c *Counter) Load() int64 { return c.v.Load() }

// Gauge goes up and down.
type Gauge struct{ v atomic.Int64 }

// Add moves the gauge by n, which may be negative.
func (g *Gauge) Add(n int64) { g.v.Add(n) }

// Load is the gauge now.
func (g *Gauge) Load() int64 { return g.v.Load() }

// LatencyBounds are the histogram buckets, in seconds: from a tenth of a
// millisecond, where a forward on one host lands, to ten seconds, where a
// write times out.
var LatencyBounds = []float64{0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Histogram counts durations into buckets.
type Histogram struct {
	bounds []float64
	counts []atomic.Int64 // one per bound, and one past the last
	sumNs  atomic.Int64
	n      atomic.Int64
}

func newHistogram(bounds []float64) *Histogram {
	return &Histogram{bounds: bounds, counts: make([]atomic.Int64, len(bounds)+1)}
}

// Observe counts one duration.
func (h *Histogram) Observe(d time.Duration) {
	i := sort.SearchFloat64s(h.bounds, d.Seconds())
	h.counts[i].Add(1)
	h.sumNs.Add(int64(d))
	h.n.Add(1)
}

// Since counts the time since t.
func (h *Histogram) Since(t time.Time) { h.Observe(time.Since(t)) }

// Count is how many durations it has counted.
func (h *Histogram) Count() int64 { return h.n.Load() }

// snapshot is the bucket counts now.
func (h *Histogram) snapshot() []int64 {
	out := make([]int64, len(h.counts))
	for i := range h.counts {
		out[i] = h.counts[i].Load()
	}
	return out
}

// quantile is the upper bound of the bucket that holds the q-th quantile of
// counts, a delta between two snapshots, or 0 without any.
func (h *Histogram) quantile(counts []int64, q float64) float64 { return quantile(h.bounds, counts, q) }

func quantile(bounds []float64, counts []int64, q float64) float64 {
	var total int64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	rank := int64(math.Ceil(q * float64(total)))
	var seen int64
	for i, c := range counts {
		seen += c
		if seen >= rank {
			if i == len(bounds) {
				return math.Inf(1)
			}
			return bounds[i]
		}
	}
	return math.Inf(1)
}

type kind int

const (
	counter kind = iota
	gauge
	histogram
)

func (k kind) String() string { return [...]string{"counter", "gauge", "histogram"}[k] }

// series is one name with one set of labels.
type series struct {
	name, help, labels string
	kind               kind
	c                  *Counter
	g                  *Gauge
	f                  func() int64
	h                  *Histogram
}

// Set is a collection of series.
type Set struct {
	mu     sync.Mutex
	series []*series
}

// Default holds every series the service keeps.
var Default = &Set{}

// labels renders pairs as name="value",..., in the order given.
func labels(pairs []string) string {
	if len(pairs)%2 != 0 {
		panic("metrics: labels come in pairs")
	}
	var b strings.Builder
	for i := 0; i < len(pairs); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", pairs[i], pairs[i+1])
	}
	return b.String()
}

func (s *Set) add(x *series) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, y := range s.series {
		if y.name == x.name && y.labels == x.labels {
			panic("metrics: " + x.name + "{" + x.labels + "} twice")
		}
	}
	s.series = append(s.series, x)
}

// Counter adds a counter. pairs are label names and values.
func (s *Set) Counter(name, help string, pairs ...string) *Counter {
	c := &Counter{}
	s.add(&series{name: name, help: help, labels: labels(pairs), kind: counter, c: c})
	return c
}

// Gauge adds a gauge the caller moves.
func (s *Set) Gauge(name, help string, pairs ...string) *Gauge {
	g := &Gauge{}
	s.add(&series{name: name, help: help, labels: labels(pairs), kind: gauge, g: g})
	return g
}

// GaugeFunc adds a gauge read from f when the series are written. f must be
// cheap and must not block.
func (s *Set) GaugeFunc(name, help string, f func() int64, pairs ...string) {
	s.add(&series{name: name, help: help, labels: labels(pairs), kind: gauge, f: f})
}

// Histogram adds a latency histogram with LatencyBounds.
func (s *Set) Histogram(name, help string, pairs ...string) *Histogram {
	h := newHistogram(LatencyBounds)
	s.add(&series{name: name, help: help, labels: labels(pairs), kind: histogram, h: h})
	return h
}

func (x *series) value() int64 {
	switch {
	case x.c != nil:
		return x.c.Load()
	case x.g != nil:
		return x.g.Load()
	default:
		return x.f()
	}
}

// WriteTo writes every series in Prometheus' text format.
func (s *Set) WriteTo(w io.Writer) (int64, error) {
	s.mu.Lock()
	all := slices.Clone(s.series)
	s.mu.Unlock()
	sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })
	var b strings.Builder
	last := ""
	for _, x := range all {
		if x.name != last {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", x.name, x.help, x.name, x.kind)
			last = x.name
		}
		if x.kind != histogram {
			fmt.Fprintf(&b, "%s%s %d\n", x.name, braces(x.labels), x.value())
			continue
		}
		counts := x.h.snapshot()
		var cum int64
		for i, c := range counts {
			cum += c
			le := "+Inf"
			if i < len(x.h.bounds) {
				le = fmt.Sprintf("%g", x.h.bounds[i])
			}
			fmt.Fprintf(&b, "%s_bucket%s %d\n", x.name, braces(join(x.labels, `le="`+le+`"`)), cum)
		}
		fmt.Fprintf(&b, "%s_sum%s %g\n", x.name, braces(x.labels), float64(x.h.sumNs.Load())/1e9)
		fmt.Fprintf(&b, "%s_count%s %d\n", x.name, braces(x.labels), x.h.n.Load())
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

func braces(l string) string {
	if l == "" {
		return ""
	}
	return "{" + l + "}"
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "," + b
}

// ServeHTTP answers GET /metrics.
func (s *Set) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = s.WriteTo(w)
}

// The service's series, named in one place so each name keeps one help
// line. Each call adds a series; call each once per label value, from a
// package variable.

// Drop counts what the service dropped for one reason.
func Drop(reason string) *Counter {
	return Default.Counter("ftwcloud_drops_total", "Messages and connections the service dropped, by reason.", "reason", reason)
}

// Sockets is the open sockets of one kind.
func Sockets(kind string) *Gauge {
	return Default.Gauge("ftwcloud_sockets", "Open sockets, by kind.", "kind", kind)
}

// TransportSockets is the open sockets of one kind over one transport,
// quic or websocket.
func TransportSockets(kind, transport string) *Gauge {
	return Default.Gauge("ftwcloud_transport_sockets", "Open sockets, by kind and transport.", "kind", kind, "transport", transport)
}

// BytesOut counts the bytes of the messages the service writes to one kind
// of socket. TLS, WebSocket and QUIC framing come on top.
func BytesOut(kind string) *Counter {
	return Default.Counter("ftwcloud_bytes_out_total", "Bytes of messages written to sockets, by kind; TLS, WebSocket and QUIC framing not counted.", "kind", kind)
}

// Handshake times one kind of handshake, from the upgrade or the request to
// the answer that ends it.
func Handshake(kind string) *Histogram {
	return Default.Histogram("ftwcloud_handshake_seconds", "From a connection's upgrade, or a request's arrival, to the end of its handshake, by kind.", "kind", kind)
}

// Forward times one path through the service, from a message's arrival to
// its write on the next socket, queueing included.
func Forward(path string) *Histogram {
	return Default.Histogram("ftwcloud_forward_seconds", "From a message's arrival to its write on the next socket, queueing included, by path.", "path", path)
}

// WrongShard counts connections and requests for a home another shard holds.
func WrongShard(kind string) *Counter {
	return Default.Counter("ftwcloud_wrong_shard_total", "Connections and requests for a home another shard holds, by kind.", "kind", kind)
}

// Runtime adds the Go runtime's heap, the memory it holds from the system,
// and its goroutines. Call it once.
func Runtime() {
	read := func(name string) func() int64 {
		return func() int64 {
			s := []runtimemetrics.Sample{{Name: name}}
			runtimemetrics.Read(s)
			if s[0].Value.Kind() != runtimemetrics.KindUint64 {
				return 0
			}
			return int64(s[0].Value.Uint64())
		}
	}
	Default.GaugeFunc("ftwcloud_go_heap_bytes", "Bytes in live and not yet swept heap objects.", read("/memory/classes/heap/objects:bytes"))
	Default.GaugeFunc("ftwcloud_go_memory_bytes", "Bytes the Go runtime holds from the system.", read("/memory/classes/total:bytes"))
	Default.GaugeFunc("ftwcloud_go_goroutines", "Goroutines.", read("/sched/goroutines:goroutines"))
}
