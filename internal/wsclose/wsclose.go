// Package wsclose ends a WebSocket as RFC 6455 asks: send a close, wait for
// the peer's, then close the TCP connection. A server that closes right after
// its close frame, with the peer's data still unread, makes Linux send a
// reset, and the peer sees 1006 instead of the code it was meant to read,
// such as 4421 with the right shard or 4503 with the spread.
//
// A Set tracks every socket a handler holds from the upgrade on, so a drain
// reaches those still in their handshake too. A socket is a WebSocket or a
// QUIC connection (package quicdoor), whose close is its application error.
package wsclose

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/srcfl/ftw-cloud/internal/wire"
)

// Wait is how long a close waits for the peer's.
const Wait = time.Second

// Socket is one tracked socket.
type Socket struct {
	Conn wire.Conn
	sent atomic.Bool
}

// Close sends one close frame, the first one asked for, and makes the read
// that waits for the peer's answer end within Wait. A timer closes the
// connection after twice Wait in any case. False means a close was sent
// already.
func (s *Socket) Close(code int, reason string) bool {
	if !s.sent.CompareAndSwap(false, true) {
		return false
	}
	// gorilla lets WriteControl run beside a data write, so a write stuck
	// on a full socket does not hold the close back.
	_ = s.Conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(Wait))
	_ = s.Conn.SetReadDeadline(time.Now().Add(Wait))
	time.AfterFunc(2*Wait, func() { _ = s.Conn.Close() })
	return true
}

// AwaitPeer reads and discards until the peer's close or the deadline Close
// set. Only the goroutine that reads the socket may call it.
func (s *Socket) AwaitPeer() {
	for {
		if _, _, err := s.Conn.ReadMessage(); err != nil {
			return
		}
	}
}

// Set is the sockets a handler holds now.
type Set struct {
	mu sync.Mutex
	m  map[*Socket]struct{}
}

// Add tracks a socket from its upgrade on.
func (t *Set) Add(c wire.Conn) *Socket {
	s := &Socket{Conn: c}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[*Socket]struct{}{}
	}
	t.m[s] = struct{}{}
	return s
}

// Remove stops tracking a socket, when its handler returns.
func (t *Set) Remove(s *Socket) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, s)
}

// Len is how many sockets are tracked.
func (t *Set) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// CloseAll sends every tracked socket a close with code and reason, side by
// side, and returns how many there were.
func (t *Set) CloseAll(code int, reason string) int {
	t.mu.Lock()
	all := make([]*Socket, 0, len(t.m))
	for s := range t.m {
		all = append(all, s)
	}
	t.mu.Unlock()
	for _, s := range all {
		go s.Close(code, reason)
	}
	return len(all)
}

// WaitEmpty waits, at most d, until no socket is tracked, and returns how
// many still are.
func (t *Set) WaitEmpty(d time.Duration) int {
	deadline := time.Now().Add(d)
	for t.Len() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return t.Len()
}
