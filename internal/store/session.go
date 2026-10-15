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
	// TunQueue is how many tun messages may wait for one phone, apart from
	// the envelopes, so a reading never waits behind the tunnel or the
	// other way round. Past it a message is dropped, which Noise transport
	// survives at the cost of one frame.
	TunQueue = 256

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
	// tun carries the box's side of the phone's own session.
	tun chan cloudwire.AppTun
	// sid is the box session the phone runs now, when hasSid.
	sid    uint32
	hasSid bool
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
	// under the lock that roster changes take. A pairing hash is spent here,
	// once the session is sure to open, so a busy home does not burn it.
	if x.pairing {
		if len(x.h.sessions) >= MaxSessionsPerHome {
			return Snapshot{}, nil, ErrBusy
		}
		if !x.h.spendLocked(x.pair, x.s.now()) {
			return Snapshot{}, nil, ErrDenied
		}
	} else if _, _, ok := x.s.access(x.id, x.h, byKey(x.device.Key)); !ok {
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
	sess := &Session{x: x, c: make(chan []byte, SessionQueue), tun: make(chan cloudwire.AppTun, TunQueue),
		done: make(chan struct{})}
	x.h.sessions[sess] = struct{}{}
	return x.snapshotLocked(), sess, nil
}

// C carries the envelopes to forward.
func (s *Session) C() <-chan []byte { return s.c }

// Tun carries the box's tun messages for this phone.
func (s *Session) Tun() <-chan cloudwire.AppTun { return s.tun }

// SetSid records the box session the phone runs now, so the end of the
// box's uplink reaches it.
func (s *Session) SetSid(sid uint32) {
	s.x.h.mu.Lock()
	defer s.x.h.mu.Unlock()
	s.sid, s.hasSid = sid, true
}

// Ended queues the end of the phone's box session sid, from the service
// itself, as when no box took its first message.
func (s *Session) Ended(sid uint32) {
	s.x.h.mu.Lock()
	defer s.x.h.mu.Unlock()
	if s.ended {
		return
	}
	select {
	case s.tun <- cloudwire.AppTun{Sid: sid}:
	default:
	}
}

// Tun hands one tun from the box to the session of the device it names.
// False when no session of that device is open. A full queue drops it.
func (x *Handle) Tun(t cloudwire.Tun) bool {
	if x.kind != Box {
		return false
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	for sess := range x.h.sessions {
		if sess.ended || sess.x.device.ID != t.Dev {
			continue
		}
		select {
		case sess.tun <- cloudwire.AppTun{Sid: t.Sid, D: t.D}:
		default:
		}
		return true
	}
	return false
}

// tunGoneLocked tells each phone whose box session rode the uplink that
// has gone that the session ended. The caller holds the home's lock.
func (h *home) tunGoneLocked() {
	for sess := range h.sessions {
		if !sess.hasSid || sess.ended {
			continue
		}
		select {
		case sess.tun <- cloudwire.AppTun{Sid: sess.sid}:
		default:
		}
		sess.hasSid = false
	}
}

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

// Device is the roster entry this device matched. A phone admitted for
// pairing takes its entry when the roster lists it, so it is read under the
// home's lock.
func (x *Handle) Device() cloudwire.Device {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.device
}

// Scopes is the device's effective scope.
func (x *Handle) Scopes() []string {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.scopes
}

// Home is the home this handle reaches.
func (x *Handle) Home() string { return x.id }

// MayRead reports whether the device may read a class.
func (x *Handle) MayRead(class string) bool {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.mayRead(class)
}
