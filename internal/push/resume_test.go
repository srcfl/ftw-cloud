package push

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// restart is the same registry under a new service, as after a deploy.
func (r *rig) restart(t *testing.T) {
	t.Helper()
	r.svc = New(r.reg, r.apple, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.svc.now, r.svc.after = r.clock.time, r.clock.after
	if err := r.svc.Resume(); err != nil {
		t.Fatal(err)
	}
}

// A restart in the middle of an outage keeps what was left of the wait.
func TestARestartKeepsTheWaitForBoxUnreachable(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, "")
	r.clock.advance(400 * time.Second)
	r.restart(t)
	r.clock.advance(199 * time.Second)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatal("sent before ten minutes")
	}
	r.clock.advance(2 * time.Second)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d at ten minutes, across a restart", n)
	}
}

// An alert already sent is not sent again by a restart.
func TestARestartDoesNotRepeatBoxUnreachable(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, "")
	r.clock.advance(601 * time.Second)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d", n)
	}
	r.restart(t)
	r.clock.advance(time.Hour)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d after a restart", n)
	}
}

// A box that was connected when the service stopped gets the whole wait to
// come back, and nothing is sent when it does.
func TestARestartGivesAConnectedBoxItsWholeWait(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.restart(t)
	r.clock.advance(30 * time.Second)
	r.svc.BoxConnected(r.home)
	r.clock.advance(time.Hour)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatalf("sent %d for a box that came back", n)
	}

	r.restart(t)
	r.clock.advance(601 * time.Second)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d for a box that never came back after a restart", n)
	}
}
