package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Pacing. The door limits tun per home and direction and drops what is
// over. Noise transport survives a lost message, but a call whose answer
// lost one waits out its time, and a home's phones share the same limits.
// So the agents' calls on one home are paced to a quarter of them: a burst
// of calls, then a few a second, and a budget of bytes answered.
const (
	paceShare          = 4
	paceCallBurst      = 20
	paceCallsPerSecond = 4
	paceByteBurst      = cloudwire.TunByteBurst / paceShare
	paceBytesPerSecond = cloudwire.TunBytesPerSecond / paceShare
	// paceWaitMost is the longest a call waits for its turn in the budget
	// before it is told to slow down.
	paceWaitMost = 3 * time.Second
)

var errSlowDown = userError("This home's box takes only a few requests a second. Wait a moment and try again.")

// pacer is one home's budget.
type pacer struct {
	mu           sync.Mutex
	calls, bytes float64
	at           time.Time
}

func newPacer(now time.Time) *pacer {
	return &pacer{calls: paceCallBurst, bytes: paceByteBurst, at: now}
}

func (pc *pacer) refill(now time.Time) {
	dt := now.Sub(pc.at).Seconds()
	if dt > 0 {
		pc.calls = min(paceCallBurst, pc.calls+dt*paceCallsPerSecond)
		pc.bytes = min(paceByteBurst, pc.bytes+dt*paceBytesPerSecond)
		pc.at = now
	}
}

// delay is how long until a call fits, zero when it fits now.
func (pc *pacer) delay(now time.Time) time.Duration {
	pc.refill(now)
	var d time.Duration
	if pc.calls < 1 {
		d = time.Duration((1 - pc.calls) / paceCallsPerSecond * float64(time.Second))
	}
	if pc.bytes < 0 {
		d = max(d, time.Duration(-pc.bytes/paceBytesPerSecond*float64(time.Second)))
	}
	return d
}

// wait takes one call from the home's budget, waiting a little if it must.
func (pc *pacer) wait(ctx context.Context, now func() time.Time) error {
	for {
		pc.mu.Lock()
		d := pc.delay(now())
		if d == 0 {
			pc.calls--
			pc.mu.Unlock()
			return nil
		}
		pc.mu.Unlock()
		if d > paceWaitMost {
			return errSlowDown
		}
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return errSlowDown
		}
	}
}

// spend counts the bytes a call brought back.
func (pc *pacer) spend(n int, now time.Time) {
	pc.mu.Lock()
	pc.refill(now)
	pc.bytes -= float64(n)
	pc.mu.Unlock()
}

// pace is the home's budget, made on first use.
func (p *Pool) pace(home string) *pacer {
	p.mu.Lock()
	defer p.mu.Unlock()
	pc := p.paces[home]
	if pc == nil {
		pc = newPacer(p.now())
		p.paces[home] = pc
	}
	return pc
}

// forgetFullPaces drops budgets that have refilled: a home not called on
// for a while starts afresh. The caller holds p.mu.
func (p *Pool) forgetFullPacesLocked(now time.Time) {
	for home, pc := range p.paces {
		pc.mu.Lock()
		pc.refill(now)
		full := pc.calls >= paceCallBurst && pc.bytes >= paceByteBurst
		pc.mu.Unlock()
		if full {
			delete(p.paces, home)
		}
	}
}
