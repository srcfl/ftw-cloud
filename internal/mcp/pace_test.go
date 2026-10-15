package mcp

import (
	"context"
	"testing"
	"time"
)

// The budget: a burst of calls, then a few a second; a large answer makes
// the next calls wait; a wait past a few seconds is a "slow down".
func TestPacing(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	pc := newPacer(now, PaceBurst, PacePerSecond)
	ctx := context.Background()
	for i := range PaceBurst {
		if pc.delay(now) != 0 {
			t.Fatalf("call %d of the burst waits", i)
		}
		if err := pc.wait(ctx, clock); err != nil {
			t.Fatal(err)
		}
	}
	rate := PacePerSecond
	if d := pc.delay(now); d != time.Duration(float64(time.Second)/rate) {
		t.Fatalf("after the burst a call waits %s", d)
	}
	// No rolling minute holds more than the box's 60 reads.
	start, calls := now, PaceBurst
	for now.Sub(start) < time.Minute {
		now = now.Add(pc.delay(now))
		if now.Sub(start) >= time.Minute {
			break
		}
		if err := pc.wait(ctx, clock); err != nil {
			t.Fatal(err)
		}
		calls++
	}
	if calls > 60 {
		t.Fatalf("%d calls in a minute", calls)
	}
	// A second's worth of the home's bytes and more: the next call waits.
	now = now.Add(time.Minute)
	pc.spend(paceByteBurst+paceBytesPerSecond, now)
	if d := pc.delay(now); d < 900*time.Millisecond || d > 1100*time.Millisecond {
		t.Fatalf("after a large answer a call waits %s", d)
	}
	pc.spend(10*paceBytesPerSecond, now)
	if err := pc.wait(ctx, clock); err != errSlowDown {
		t.Fatalf("a long wait: %v", err)
	}
}

// Many calls on one home in a row: paced, all answered, and the door drops
// nothing.
func TestManyCallsLoseNothing(t *testing.T) {
	w := newWorld(t, func(w *world) { w.pool.PaceBurst, w.pool.PacePerSecond = 5, 8 })
	b := w.connectBox()
	a := w.connect(b, "")
	start := time.Now()
	const n = 13
	for i := range n {
		if _, isErr, text := a.call("health.get", nil); isErr {
			t.Fatalf("call %d: %s", i, text)
		}
	}
	if d := w.up.TunDropped.Load(); d != 0 {
		t.Fatalf("the door dropped %d messages", d)
	}
	if took := time.Since(start); took < 900*time.Millisecond {
		t.Fatalf("%d calls took %s: not paced", n, took)
	}
}
