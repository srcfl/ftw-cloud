package push

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// flakyApple fails the first n sends with status, then takes everything.
type flakyApple struct {
	mu     sync.Mutex
	n      int
	status int
	sent   []apns.Notification
}

func (f *flakyApple) Send(_ context.Context, n apns.Notification) (apns.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, n)
	if f.n > 0 {
		f.n--
		return apns.Result{Status: f.status}, nil
	}
	return apns.Result{Status: 200}, nil
}

func (f *flakyApple) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

// An alert that Apple cannot take for a while goes again, after a wait that
// doubles, and arrives.
func TestAnAlertAppleCouldNotTakeGoesAgain(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 2, status: 503}
	r.svc.sender = apple
	_ = r.register(t, r.owner, r.all, "owner-token")
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if apple.count() != 1 {
		t.Fatalf("sent %d", apple.count())
	}
	r.clock.advance(alertRetryAfter)
	r.drain()
	if apple.count() != 2 {
		t.Fatalf("sent %d after the first wait", apple.count())
	}
	r.clock.advance(alertRetryAfter) // the second wait is twice the first
	r.drain()
	if apple.count() != 2 {
		t.Fatalf("sent %d before the doubled wait was over", apple.count())
	}
	r.clock.advance(alertRetryAfter)
	r.drain()
	if apple.count() != 3 {
		t.Fatalf("sent %d after the doubled wait", apple.count())
	}
	r.clock.advance(time.Hour)
	r.drain()
	if apple.count() != 3 {
		t.Fatalf("an alert Apple took went again: %d", apple.count())
	}
}

// An alert is given up after alertTries, and only the devices Apple did not
// take hear it again.
func TestAnAlertIsGivenUpAfterItsTries(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 100, status: 429}
	r.svc.sender = apple
	_ = r.register(t, r.owner, r.all, "owner-token")
	r.svc.Event(r.home, []byte{0xa0})
	for range 10 {
		r.drain()
		r.clock.advance(time.Minute)
	}
	if apple.count() != alertTries {
		t.Fatalf("sent %d times, want %d", apple.count(), alertTries)
	}
}

// Three price changes before the worker gets to a home are one widgets
// push.
func TestWidgetPushesForOneHomeMerge(t *testing.T) {
	r := newRig(t)
	box := newBoxSigner(t)
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	t0 := int64(1_791_820_800_000)
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, t0, 48, 12))
	before := widgetsMerged.Load()
	for i := range 3 {
		r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, t0, 48, 24+i))
	}
	if got := r.taken(); len(got) != 1 {
		t.Fatalf("%d widgets pushes for one home", len(got))
	}
	if widgetsMerged.Load()-before != 2 {
		t.Fatalf("merged %d", widgetsMerged.Load()-before)
	}
}

// Alerts have workers of their own: a queue of widget pushes held back by
// the rate does not delay an alert.
func TestAnAlertDoesNotWaitBehindWidgets(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{}
	r.svc.sender = apple
	r.svc.now = time.Now
	_ = r.register(t, r.owner, r.all, "owner-token")
	// The widget worker may never pass.
	r.svc.gate = gate{rate: 1e-9, burst: 1, sleep: func(ctx context.Context, _ time.Duration) bool {
		<-ctx.Done()
		return false
	}}
	for i := range 1000 {
		r.svc.queueWidgets(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.svc.Run(ctx)
	start := time.Now()
	r.svc.Event(r.home, []byte{0xa0})
	for apple.count() == 0 {
		if time.Since(start) > 2*time.Second {
			t.Fatal("the alert waited behind widgets")
		}
		time.Sleep(time.Millisecond)
	}
	if n := r.svc.Flush(time.Second); n != 0 {
		t.Fatalf("%d alerts left after a flush", n)
	}
}

func TestTheQueueIsBoundedAndKeepsOrder(t *testing.T) {
	q := newFIFO[int](3, &metrics.Gauge{})
	for i := range 3 {
		if !q.push(i) {
			t.Fatal("refused below its bound")
		}
	}
	if q.push(3) {
		t.Fatal("took one past its bound")
	}
	for want := range 3 {
		if got, ok := q.pop(); !ok || got != want {
			t.Fatalf("pop %d, %v; want %d", got, ok, want)
		}
	}
	if _, ok := q.pop(); ok {
		t.Fatal("popped from an empty queue")
	}
	// A long run through the queue keeps its memory to what waits.
	for i := range 5000 {
		q.push(i)
		q.pop()
	}
	if cap(q.items) > 2048 {
		t.Fatalf("queue holds %d slots for nothing", cap(q.items))
	}
}

func TestTheGatePassesItsRate(t *testing.T) {
	now := time.Unix(0, 0)
	var slept time.Duration
	g := gate{rate: 20, burst: 2, tokens: 2, nowForTesting: func() time.Time { return now },
		sleep: func(_ context.Context, d time.Duration) bool {
			slept += d
			now = now.Add(d)
			return true
		}}
	for range 22 {
		g.wait(context.Background())
	}
	// Two in the burst, then twenty at 20 a second.
	if slept < 950*time.Millisecond || slept > 1050*time.Millisecond {
		t.Fatalf("22 passes slept %s", slept)
	}
}
