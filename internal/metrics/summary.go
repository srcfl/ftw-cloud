package metrics

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Summarise writes one line every period to w until ctx ends: how much each
// counter rose over the period, each gauge now, and p50, p95 and p99 of each
// histogram over the period, in milliseconds. The line is CloudWatch's
// embedded metric format, so once the host ships its logs to CloudWatch Logs
// each field becomes a metric in the FTWCloud namespace, with the shard as
// its one dimension. It names no home.
func (s *Set) Summarise(ctx context.Context, w io.Writer, shard string, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	last := s.state()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			cur := s.state()
			line, err := s.line(last, cur, shard, now)
			last = cur
			if err == nil {
				_, _ = w.Write(append(line, '\n'))
			}
		}
	}
}

// state is every counter's count and every histogram's buckets now.
type state map[*series][]int64

func (s *Set) state() state {
	s.mu.Lock()
	all := slices.Clone(s.series)
	s.mu.Unlock()
	out := state{}
	for _, x := range all {
		if x.kind == histogram {
			out[x] = x.h.snapshot()
		} else {
			out[x] = []int64{x.value()}
		}
	}
	return out
}

var unsafeName = regexp.MustCompile(`[^a-z0-9_]+`)

// field is a series' name in the line: without the ftwcloud_ prefix and
// _total suffix, with its label values after it.
func field(x *series) string {
	name := strings.TrimSuffix(strings.TrimPrefix(x.name, "ftwcloud_"), "_total")
	for _, part := range strings.Split(x.labels, ",") {
		if _, v, ok := strings.Cut(part, "="); ok {
			name += "_" + strings.Trim(v, `"`)
		}
	}
	return unsafeName.ReplaceAllString(strings.ToLower(name), "_")
}

type emfMetric struct {
	Name string `json:"Name"`
	Unit string `json:"Unit"`
}

type emfDirective struct {
	Namespace  string      `json:"Namespace"`
	Dimensions [][]string  `json:"Dimensions"`
	Metrics    []emfMetric `json:"Metrics"`
}

// emfMax is CloudWatch's limit on metrics per directive.
const emfMax = 100

func (s *Set) line(last, cur state, shard string, now time.Time) ([]byte, error) {
	fields := map[string]any{"Shard": shard}
	var metrics []emfMetric
	put := func(name, unit string, v float64) {
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return
		}
		fields[name] = v
		metrics = append(metrics, emfMetric{Name: name, Unit: unit})
	}
	keys := make([]*series, 0, len(cur))
	for x := range cur {
		keys = append(keys, x)
	}
	slices.SortFunc(keys, func(a, b *series) int { return strings.Compare(field(a), field(b)) })
	for _, x := range keys {
		now, before := cur[x], last[x]
		switch x.kind {
		case counter:
			var prev int64
			if len(before) == 1 {
				prev = before[0]
			}
			put(field(x), "Count", float64(now[0]-prev))
		case gauge:
			put(field(x), "Count", float64(now[0]))
		case histogram:
			delta := slices.Clone(now)
			for i := range delta {
				if i < len(before) {
					delta[i] -= before[i]
				}
			}
			var n int64
			for _, c := range delta {
				n += c
			}
			put(field(x)+"_n", "Count", float64(n))
			if n == 0 {
				continue
			}
			for _, q := range []struct {
				name string
				q    float64
			}{{"p50", 0.5}, {"p95", 0.95}, {"p99", 0.99}} {
				put(field(x)+"_"+q.name, "Milliseconds", x.h.quantile(delta, q.q)*1000)
			}
		}
	}
	var directives []emfDirective
	for len(metrics) > 0 {
		n := min(len(metrics), emfMax)
		directives = append(directives, emfDirective{Namespace: "FTWCloud", Dimensions: [][]string{{"Shard"}}, Metrics: metrics[:n]})
		metrics = metrics[n:]
	}
	fields["_aws"] = map[string]any{"Timestamp": now.UnixMilli(), "CloudWatchMetrics": directives}
	return json.Marshal(fields)
}
