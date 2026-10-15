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

// An alert goes again until it expires, then is given up and counted.
func TestAnAlertGoesAgainUntilItExpires(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 1000, status: 429}
	r.svc.sender = apple
	_ = r.register(t, r.owner, r.all, "owner-token")
	failed := apnsResults[cloudwire.PushKindAlert]["failed"].Load()
	r.svc.Event(r.home, []byte{0xa0})
	for range 15 {
		r.drain()
		r.clock.advance(time.Minute)
	}
	sent := apple.count()
	// Waits of 2, 4, 8 … 256 s, each up to a quarter shorter, fit in the
	// event's ten minutes about nine times.
	if sent < 8 || sent > 12 {
		t.Fatalf("sent %d times in ten minutes", sent)
	}
	r.clock.advance(time.Hour)
	r.drain()
	if apple.count() != sent {
		t.Fatal("an expired alert went again")
	}
	if apnsResults[cloudwire.PushKindAlert]["failed"].Load() == failed {
		t.Fatal("the given-up alert was not counted")
	}
}

// box.unreachable is recorded as told only once a phone took it, so an
// alert that failed goes again after a restart.
func TestBoxUnreachableIsToldOnlyOnceAPhoneTookIt(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 1, status: 503}
	r.svc.sender = apple
	_ = r.register(t, r.owner, r.all, "owner-token")
	r.connected()
	r.gone("")
	r.clock.advance(601 * time.Second)
	r.drain()
	if apple.count() != 1 {
		t.Fatalf("sent %d", apple.count())
	}
	told := func() bool {
		away, _ := r.reg.AwayAll()
		return len(away) == 1 && away[0].Told
	}
	if told() {
		t.Fatal("told before any phone took it")
	}
	r.clock.advance(alertRetryAfter)
	r.drain()
	if apple.count() != 2 || !told() {
		t.Fatalf("sent %d, told %v", apple.count(), told())
	}
}

// A device suspended between two tries gets nothing on the second.
func TestARetryGoesOnlyToDevicesThatMayStillGetIt(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 2, status: 503}
	r.svc.sender = apple
	_ = r.register(t, r.owner, r.all, "owner-token")
	viewer := r.viewer
	viewer.Scopes = r.all
	_ = r.register(t, viewer, r.all, "viewer-token")
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	_ = r.reg.Suspend(r.home, viewer.ID, viewer.Epoch, r.clock.time())
	r.clock.advance(alertRetryAfter)
	r.drain()
	apple.mu.Lock()
	defer apple.mu.Unlock()
	if len(apple.sent) != 3 || string(apple.sent[2].DeviceToken) != "owner-token" {
		var got []string
		for _, n := range apple.sent {
			got = append(got, string(n.DeviceToken))
		}
		t.Fatalf("sent %v", got)
	}
}

// After many failures in a row the breaker holds pushes back, and one
// success closes it.
func TestTheBreakerOpensAfterFailuresInARow(t *testing.T) {
	var b breaker
	b.trips = 3
	b.result(true)
	b.result(true)
	b.result(false)
	b.result(true)
	b.result(true)
	if time.Until(b.openUntil) > 0 {
		t.Fatal("open without three failures in a row")
	}
	b.result(true)
	if time.Until(b.openUntil) <= 0 {
		t.Fatal("closed after three failures in a row")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if b.wait(ctx) {
		t.Fatal("an open breaker let a push through")
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

// Flush counts an alert that waits to go again, so the exit says it is
// lost rather than dropping it without a word.
func TestFlushCountsAlertsWaitingToGoAgain(t *testing.T) {
	r := newRig(t)
	r.svc.sender = &flakyApple{n: 100, status: 503}
	_ = r.register(t, r.owner, r.all, "owner-token")
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if n := r.svc.Flush(50 * time.Millisecond); n != 1 {
		t.Fatalf("Flush left %d, want the one waiting to go again", n)
	}
	r.clock.advance(alertRetryAfter)
	r.svc.alerts.pop()
	if n := r.svc.Flush(50 * time.Millisecond); n != 0 {
		t.Fatalf("Flush left %d after the retry was taken", n)
	}
}

// A widgets push Apple could not take goes once more, and no more.
func TestAFailedWidgetsPushGoesOnceMore(t *testing.T) {
	r := newRig(t)
	apple := &flakyApple{n: 2, status: 503}
	r.svc.sender = apple
	box := newBoxSigner(t)
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	t0 := int64(1_791_820_800_000)
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, t0, 48, 12))
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, t0, 48, 24))
	r.drain()
	if apple.count() != 1 {
		t.Fatalf("sent %d", apple.count())
	}
	r.clock.advance(widgetRetryAfter)
	r.drain()
	if apple.count() != 2 {
		t.Fatalf("sent %d after the retry", apple.count())
	}
	r.clock.advance(time.Hour)
	r.drain()
	if apple.count() != 2 {
		t.Fatalf("a widgets push went a third time: %d", apple.count())
	}
}
