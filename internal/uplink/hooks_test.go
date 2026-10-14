package uplink

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// heard records what the uplink tells push.
type heard struct {
	mu      sync.Mutex
	events  [][]byte
	classes []string
	rosters []uint64
	gone    []string
	conns   int
}

func listen(s *service) *heard {
	h := &heard{}
	s.up.OnConnect = func(string) { h.mu.Lock(); h.conns++; h.mu.Unlock() }
	s.up.OnHeld = func(home, class string, env []byte) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.classes = append(h.classes, class)
		if class == cloudwire.MsgEvent {
			h.events = append(h.events, env)
		}
	}
	s.up.OnRoster = func(home string, r *cloudwire.Roster) {
		h.mu.Lock()
		h.rosters = append(h.rosters, r.RosterSeq)
		h.mu.Unlock()
	}
	s.up.OnGone = func(home, why string) {
		h.mu.Lock()
		h.gone = append(h.gone, why)
		h.mu.Unlock()
	}
	return h
}

func (h *heard) count(of func(*heard) int) func() int {
	return func() int {
		h.mu.Lock()
		defer h.mu.Unlock()
		return of(h)
	}
}

// A signed event reaches push as the envelope the box sent, and only a
// signed one.
func TestAnEventReachesPushUnchanged(t *testing.T) {
	s := newService(t)
	h := listen(s)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeEventsRead))
	sent := b.send(cloudwire.MsgEvent, cloudwire.Event{Header: b.header(), EventID: "e1",
		Kind: protocol.PushChargingInterrupted, Severity: cloudwire.SeverityWarning, Args: map[string]string{}})
	events := h.count(func(h *heard) int { return len(h.events) })
	wait(t, "the event", func() bool { return events() == 1 })
	if !bytes.Equal(h.events[0], sent) {
		t.Fatal("push got other bytes than the box sent")
	}
	if rosters := h.count(func(h *heard) int { return len(h.rosters) }); rosters() != 1 {
		t.Fatal("push did not hear the roster")
	}
}

// Every envelope the service holds reaches push with its class, so prices
// and a car plugged in can reload widgets. A roster is not held this way.
func TestEveryHeldEnvelopeReachesPushWithItsClass(t *testing.T) {
	s := newService(t)
	h := listen(s)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	b.send(cloudwire.MsgPrices, cloudwire.Prices{Header: b.header(), SpotMinor: []*int64{}, TotalMinor: []*int64{}})
	b.send(cloudwire.MsgLP, cloudwire.LP{Header: b.header(), Loadpoints: []cloudwire.Loadpoint{}, Feedback: []cloudwire.Feedback{}})
	classes := h.count(func(h *heard) int { return len(h.classes) })
	wait(t, "two held envelopes", func() bool { return classes() == 2 })
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.classes[0] != cloudwire.MsgPrices || h.classes[1] != cloudwire.MsgLP {
		t.Fatalf("push heard %v", h.classes)
	}
}

// The end of an uplink tells push why: the box's bye, or nothing when the
// socket dropped. A connection a newer one replaced says nothing.
func TestTheEndOfAnUplinkSaysWhy(t *testing.T) {
	s := newService(t)
	h := listen(s)
	gone := h.count(func(h *heard) int { return len(h.gone) })
	conns := h.count(func(h *heard) int { return h.conns })

	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	wait(t, "the connect", func() bool { return conns() == 1 })
	b.send(cloudwire.MsgBye, cloudwire.Bye{Header: b.header(), Why: cloudwire.ByeUpdate})
	wait(t, "the bye", func() bool { return gone() == 1 })
	if h.gone[0] != cloudwire.ByeUpdate {
		t.Fatalf("gone with %q", h.gone[0])
	}

	_, _ = b.connect(s, nil)
	second := *b
	second.conn = nil
	_, _ = second.connect(s, nil)
	if !b.closed() {
		t.Fatal("two uplinks for one home")
	}
	time.Sleep(100 * time.Millisecond)
	if gone() != 1 {
		t.Fatal("a replaced uplink told push the box was gone")
	}
	_ = second.conn.Close()
	wait(t, "the drop", func() bool { return gone() == 2 })
	if h.gone[1] != "" {
		t.Fatalf("a dropped socket gave %q", h.gone[1])
	}
	if conns() != 3 {
		t.Fatalf("connects %d", conns())
	}
}
