package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The service's own view, read from its /metrics at the start and end of
// the steady phase: how long a message waited inside ftwcloudd, apart from
// the harness and the operating system. It tells a queue in the service from
// one in the harness.

// promSnap is one scrape: each series by its full name with labels.
type promSnap map[string]float64

func scrape(addr string) (promSnap, error) {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + addr + "/metrics")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return parseProm(resp.Body)
}

func parseProm(r io.Reader) (promSnap, error) {
	out := promSnap{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		out[line[:i]] = v
	}
	return out, sc.Err()
}

// serverLatency is one histogram's quantiles over the steady phase, as
// bucket upper bounds in milliseconds.
type serverLatency struct {
	N   int64   `json:"n"`
	P50 float64 `json:"p50Ms"`
	P95 float64 `json:"p95Ms"`
	P99 float64 `json:"p99Ms"`
}

func (l serverLatency) String() string {
	return fmt.Sprintf("p50 ≤%s  p95 ≤%s  p99 ≤%s ms  (n %d)", bound(l.P50), bound(l.P95), bound(l.P99), l.N)
}

func bound(ms float64) string {
	if math.IsInf(ms, 1) {
		return "+Inf"
	}
	return strconv.FormatFloat(ms, 'g', 3, 64)
}

// histogram reads name{label} over the phase from two scrapes.
func histogram(before, after promSnap, name, label string) serverLatency {
	type bucket struct {
		le float64
		n  float64
	}
	var buckets []bucket
	prefix := name + "_bucket{" + label + ",le=\""
	for k, v := range after {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		leS := strings.TrimSuffix(strings.TrimPrefix(k, prefix), "\"}")
		le := math.Inf(1)
		if leS != "+Inf" {
			le, _ = strconv.ParseFloat(leS, 64)
		}
		buckets = append(buckets, bucket{le, v - before[k]})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].le < buckets[j].le })
	if len(buckets) == 0 {
		return serverLatency{}
	}
	total := buckets[len(buckets)-1].n
	q := func(p float64) float64 {
		rank := math.Ceil(p * total)
		for _, b := range buckets {
			if b.n >= rank {
				return b.le * 1000
			}
		}
		return math.Inf(1)
	}
	if total == 0 {
		return serverLatency{}
	}
	return serverLatency{N: int64(total), P50: q(0.5), P95: q(0.95), P99: q(0.99)}
}

// serverView is what the report shows from the service's metrics.
type serverView struct {
	Forward   map[string]serverLatency `json:"forward"`
	Handshake map[string]serverLatency `json:"handshake"`
	Drops     map[string]int64         `json:"drops,omitempty"`
	// At the end of the steady phase: live heap, all the runtime holds,
	// and goroutines.
	HeapMiB    float64 `json:"heapMiB"`
	GoMemMiB   float64 `json:"goMemMiB"`
	Goroutines int64   `json:"goroutines"`
}

func newServerView(before, after promSnap) *serverView {
	v := &serverView{Forward: map[string]serverLatency{}, Handshake: map[string]serverLatency{}, Drops: map[string]int64{}}
	for _, p := range []string{"envelope", "tun_up", "tun_down"} {
		v.Forward[p] = histogram(before, after, "ftwcloud_forward_seconds", `path="`+p+`"`)
	}
	for _, k := range []string{"box", "app"} {
		v.Handshake[k] = histogram(before, after, "ftwcloud_handshake_seconds", `kind="`+k+`"`)
	}
	v.HeapMiB = after["ftwcloud_go_heap_bytes"] / (1 << 20)
	v.GoMemMiB = after["ftwcloud_go_memory_bytes"] / (1 << 20)
	v.Goroutines = int64(after["ftwcloud_go_goroutines"])
	for k, n := range after {
		if r, ok := strings.CutPrefix(k, `ftwcloud_drops_total{reason="`); ok {
			if d := int64(n - before[k]); d > 0 {
				v.Drops[strings.TrimSuffix(r, `"}`)] = d
			}
		}
	}
	return v
}

// cpuSelf is the harness's own CPU time so far.
func cpuSelf() time.Duration {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
