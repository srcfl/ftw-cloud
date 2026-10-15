package push

import (
	"context"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/metrics"
)

// fifo is a bounded first-in first-out queue that never blocks the one who
// pushes. wake has a signal whenever something may be waiting.
type fifo[T any] struct {
	mu    sync.Mutex
	items []T
	head  int
	max   int
	wake  chan struct{}
	depth *metrics.Gauge
}

func newFIFO[T any](max int, depth *metrics.Gauge) *fifo[T] {
	return &fifo[T]{max: max, wake: make(chan struct{}, 1), depth: depth}
}

func (q *fifo[T]) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// push adds x, or reports false when the queue is full.
func (q *fifo[T]) push(x T) bool {
	q.mu.Lock()
	if len(q.items)-q.head >= q.max {
		q.mu.Unlock()
		return false
	}
	q.items = append(q.items, x)
	q.mu.Unlock()
	q.depth.Add(1)
	q.signal()
	return true
}

// pop takes the oldest item. Another worker is woken when more wait.
func (q *fifo[T]) pop() (T, bool) {
	q.mu.Lock()
	var zero T
	if q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
		q.mu.Unlock()
		return zero, false
	}
	x := q.items[q.head]
	q.items[q.head] = zero
	q.head++
	if q.head > 1024 && q.head*2 > len(q.items) {
		q.items, q.head = append(q.items[:0:0], q.items[q.head:]...), 0
	}
	more := q.head < len(q.items)
	q.mu.Unlock()
	q.depth.Add(-1)
	if more {
		q.signal()
	}
	return x, true
}

func (q *fifo[T]) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items) - q.head
}

// gate lets rate passes a second through, after a burst.
type gate struct {
	mu            sync.Mutex
	rate, burst   float64
	tokens        float64
	at            time.Time
	sleep         func(context.Context, time.Duration) bool
	nowForTesting func() time.Time
}

func (g *gate) now() time.Time {
	if g.nowForTesting != nil {
		return g.nowForTesting()
	}
	return time.Now()
}

// wait takes one pass, sleeping until there is one. False means ctx ended.
func (g *gate) wait(ctx context.Context) bool {
	for {
		g.mu.Lock()
		now := g.now()
		if !g.at.IsZero() {
			g.tokens = min(g.burst, g.tokens+now.Sub(g.at).Seconds()*g.rate)
		}
		g.at = now
		if g.tokens >= 1 {
			g.tokens--
			g.mu.Unlock()
			return true
		}
		need := time.Duration((1 - g.tokens) / g.rate * float64(time.Second))
		g.mu.Unlock()
		sleep := g.sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if !sleep(ctx, need) {
			return false
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
