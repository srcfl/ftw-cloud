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
	pc := newPacer(now)
	ctx := context.Background()
	for i := range paceCallBurst {
		if pc.delay(now) != 0 {
			t.Fatalf("call %d of the burst waits", i)
		}
		if err := pc.wait(ctx, clock); err != nil {
			t.Fatal(err)
		}
	}
	if d := pc.delay(now); d != time.Second/paceCallsPerSecond {
		t.Fatalf("after the burst a call waits %s", d)
	}
	now = now.Add(time.Second)
	for range paceCallsPerSecond {
		if err := pc.wait(ctx, clock); err != nil {
			t.Fatal(err)
		}
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
// nothing, where unpaced calls lost messages at its limits.
func TestManyCallsLoseNothing(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")
	start := time.Now()
	const n = paceCallBurst + 10
	for i := range n {
		if _, isErr, text := a.call("status", nil); isErr {
			t.Fatalf("call %d: %s", i, text)
		}
	}
	if d := w.up.TunDropped.Load(); d != 0 {
		t.Fatalf("the door dropped %d messages", d)
	}
	// connect made one call's worth of traffic too; the burst covers it.
	if took := time.Since(start); took < time.Duration(n-paceCallBurst-1)*time.Second/paceCallsPerSecond {
		t.Fatalf("%d calls took %s: not paced", n, took)
	}
}
