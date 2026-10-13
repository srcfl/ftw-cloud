package store

import (
	"bytes"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Limits on the phones reading one home.
const (
	// MaxSessionsPerHome bounds the phones one home can hold open at once.
	// A household has a few phones; past this the home is busy, as it is at
	// the relay.
	MaxSessionsPerHome = 16
	// SessionQueue is how many envelopes may wait for one slow phone. A box
	// sends a few a second while watched, so a phone this far behind has a
	// dead socket. It is closed and gets a fresh snapshot when it comes
	// back, rather than a stream with a hole in it.
	SessionQueue = 256

	// WebSocket close codes for the two endings that are not the protocol's
	// own: the phone left, or it fell too far behind.
	closeNormal = 1000
	closeSlow   = 1013
)

// Session is one phone's live view of its home: every envelope the box sends
// after the snapshot that the device may read, in the order the box sent
// them. The store ends it when the device's access changes.
type Session struct {
	x *Handle
	c chan []byte
	// done is closed when the store ends the session; code says why, as a
	// close code from cloudwire.
	done  chan struct{}
	code  int
	ended bool
}

// Open returns the device's snapshot and a session that receives every later
// envelope it may read. Both are taken under one lock, so nothing the box
// sends falls between them. A second session from the same device replaces
// the first.
func (x *Handle) Open() (Snapshot, *Session, error) {
	if x.kind != Device {
		return Snapshot{}, nil, ErrDenied
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	// The access checked in For may have changed since: check it again
	// under the lock that roster changes take.
	if _, _, ok := x.s.access(x.id, x.h, x.device.Key); !ok {
		return Snapshot{}, nil, ErrDenied
	}
	for sess := range x.h.sessions {
		if bytes.Equal(sess.x.device.Key, x.device.Key) {
			sess.endLocked(cloudwire.CloseReplaced)
		}
	}
	if len(x.h.sessions) >= MaxSessionsPerHome {
		return Snapshot{}, nil, ErrBusy
	}
	sess := &Session{x: x, c: make(chan []byte, SessionQueue), done: make(chan struct{})}
	x.h.sessions[sess] = struct{}{}
	return x.snapshotLocked(), sess, nil
}

// C carries the envelopes to forward.
func (s *Session) C() <-chan []byte { return s.c }

// Done is closed when the store ends the session.
func (s *Session) Done() <-chan struct{} { return s.done }

// Code is why the store ended the session, once Done is closed.
func (s *Session) Code() int {
	s.x.h.mu.Lock()
	defer s.x.h.mu.Unlock()
	return s.code
}

// Close is the phone leaving. It is safe to call more than once.
func (s *Session) Close() {
	s.x.h.mu.Lock()
	defer s.x.h.mu.Unlock()
	s.endLocked(closeNormal)
}

// deliver queues one envelope without ever blocking the box. The caller holds
// the home's lock.
func (s *Session) deliver(env []byte) {
	if s.ended {
		return
	}
	select {
	case s.c <- env:
	default:
		s.endLocked(closeSlow)
	}
}

// endLocked ends the session once. The caller holds the home's lock.
func (s *Session) endLocked(code int) {
	if s.ended {
		return
	}
	s.ended, s.code = true, code
	delete(s.x.h.sessions, s)
	close(s.done)
}

// Device is the roster entry this device matched.
func (x *Handle) Device() cloudwire.Device { return x.device }

// Scopes is the device's effective scope.
func (x *Handle) Scopes() []string { return x.scopes }

// Home is the home this handle reaches.
func (x *Handle) Home() string { return x.id }

// MayRead reports whether the device may read a class.
func (x *Handle) MayRead(class string) bool { return x.mayRead(class) }
