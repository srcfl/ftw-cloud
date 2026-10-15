package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Pacing. The box takes 60 reads a minute from an agent and refuses the
// rest; the door limits tun per home and drops what is over, and a home's
// phones share those limits. So the agents' calls on one home are paced
// under both: a burst of calls, then less than one a second, so that no
// rolling minute holds more than 60, and a quarter of the door's bytes.
const (
	paceShare = 4
	// PaceBurst and PacePerSecond: 15 + 45 in any minute.
	PaceBurst          = 15
	PacePerSecond      = 0.75
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
	burst, rate  float64
}

func newPacer(now time.Time, burst, rate float64) *pacer {
	return &pacer{calls: burst, bytes: paceByteBurst, at: now, burst: burst, rate: rate}
}

func (pc *pacer) refill(now time.Time) {
	dt := now.Sub(pc.at).Seconds()
	if dt > 0 {
		pc.calls = min(pc.burst, pc.calls+dt*pc.rate)
		pc.bytes = min(paceByteBurst, pc.bytes+dt*paceBytesPerSecond)
		pc.at = now
	}
}

// delay is how long until a call fits, zero when it fits now.
func (pc *pacer) delay(now time.Time) time.Duration {
	pc.refill(now)
	var d time.Duration
	if pc.calls < 1 {
		d = time.Duration((1 - pc.calls) / pc.rate * float64(time.Second))
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
		pc = newPacer(p.now(), p.PaceBurst, p.PacePerSecond)
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
		full := pc.calls >= pc.burst && pc.bytes >= paceByteBurst
		pc.mu.Unlock()
		if full {
			delete(p.paces, home)
		}
	}
}
