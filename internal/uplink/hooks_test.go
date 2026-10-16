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
	s.up.OnConnect = func(string, uint64) { h.mu.Lock(); h.conns++; h.mu.Unlock() }
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
	s.up.OnGone = func(home, why string, _ uint64) {
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

// A security notice reaches push as the box signed it with the readable copy
// off, and the service holds nothing of it.
func TestANoticeReachesPushWithTheCopyOff(t *testing.T) {
	s := newService(t)
	h := listen(s)
	var notices [][]byte
	var mu sync.Mutex
	s.up.OnNotice = func(_ string, env []byte) { mu.Lock(); notices = append(notices, env); mu.Unlock() }
	b := newBox(t)
	_, _ = b.connect(s, nil)
	off := b.roster()
	off.Grant = cloudwire.Grant{Controller: cloudwire.ControllerSourceful}
	b.send(cloudwire.MsgRoster, off)
	sent := b.send(cloudwire.MsgNotice, cloudwire.Notice{Header: b.header(), Kind: protocol.PushOwnerAdded})
	wait(t, "the notice", func() bool { mu.Lock(); defer mu.Unlock(); return len(notices) == 1 })
	if !bytes.Equal(notices[0], sent) {
		t.Fatal("push got other bytes than the box sent")
	}
	if classes := h.count(func(h *heard) int { return len(h.classes) }); classes() != 0 {
		t.Fatalf("the service held %v with the copy off", h.classes)
	}
	if b.closed() {
		t.Fatal("a notice closed the uplink")
	}
}

// A box that has sent no roster names no owner: its notice goes nowhere and
// costs push nothing.
func TestANoticeBeforeARosterGoesNowhere(t *testing.T) {
	s := newService(t)
	var mu sync.Mutex
	n := 0
	s.up.OnNotice = func(string, []byte) { mu.Lock(); n++; mu.Unlock() }
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgNotice, cloudwire.Notice{Header: b.header(), Kind: protocol.PushOwnerAdded})
	off := b.roster()
	off.Grant = cloudwire.Grant{Controller: cloudwire.ControllerSourceful}
	b.send(cloudwire.MsgRoster, off)
	b.send(cloudwire.MsgNotice, cloudwire.Notice{Header: b.header(), Kind: protocol.PushOwnerAdded})
	wait(t, "the notice after the roster", func() bool { mu.Lock(); defer mu.Unlock(); return n >= 1 })
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if n != 1 {
		t.Fatalf("push heard %d notices, want the one after the roster", n)
	}
}
