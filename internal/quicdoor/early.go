package quicdoor

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Early data (srcfl/ftw docs/protocol-cloud.md, "Early data"). The network can
// replay a client's first flight, and quic-go accepts what it carries. Two
// rules make a replay change nothing:
//
//   - A session ticket allows early data for cloudwire.EarlyDataFor after it
//     was issued, and resumption without early data after that.
//   - A phone's Noise message 1 in early data is answered once for each
//     initiator ephemeral key. A second copy waits for a handshake its sender
//     cannot finish, and the connection times out with nothing done.
//
// A box sends only its target in early data, and HTTP/3 requests wait for
// the handshake, so neither needs more.

// earlyTag starts the ticket's entry that says when it was issued.
var earlyTag = []byte("ftw.cloud.early.v1\x00")

// limitEarlyData makes c's tickets carry their issue time and allow early
// data only while it is under cloudwire.EarlyDataFor.
func limitEarlyData(c *tls.Config, now func() time.Time) {
	c.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		stamp := binary.BigEndian.AppendUint64(append([]byte{}, earlyTag...), uint64(now().Unix()))
		ss.Extra = append(ss.Extra, stamp)
		return c.EncryptTicket(cs, ss)
	}
	c.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		ss, err := c.DecryptTicket(identity, cs)
		if err != nil || ss == nil {
			return ss, err
		}
		if ss.EarlyData && !earlyStillAllowed(ss.Extra, now()) {
			ss.EarlyData = false
		}
		return ss, nil
	}
}

// earlyStillAllowed reads a ticket's issue time from extra.
func earlyStillAllowed(extra [][]byte, now time.Time) bool {
	for _, e := range extra {
		if len(e) == len(earlyTag)+8 && bytes.HasPrefix(e, earlyTag) {
			issued := time.Unix(int64(binary.BigEndian.Uint64(e[len(earlyTag):])), 0)
			return now.Sub(issued) < cloudwire.EarlyDataFor && !issued.After(now.Add(time.Minute))
		}
	}
	return false
}

// ephemeralBytes is the initiator's ephemeral key at the front of Noise IK
// message 1, sent in the clear.
const ephemeralBytes = 32

// maxEarlySeen bounds the guard's memory: about 48 MB at most. Past it, early
// message 1s wait for the handshake, which costs a round trip and nothing
// else.
const maxEarlySeen = 1 << 20

// earlyGuard remembers each message 1 it let through in early data, for as
// long as a ticket allows early data.
type earlyGuard struct {
	mu     sync.Mutex
	seen   map[[ephemeralBytes]byte]time.Time
	pruned time.Time
	now    func() time.Time
}

func newEarlyGuard(now func() time.Time) *earlyGuard {
	return &earlyGuard{seen: map[[ephemeralBytes]byte]time.Time{}, now: now}
}

// first reports whether msg1 is the first message 1 with its ephemeral key,
// and remembers it. False also for a message too short to be message 1, and
// while the guard is full.
func (g *earlyGuard) first(msg1 []byte) bool {
	if len(msg1) < ephemeralBytes {
		return false
	}
	var e [ephemeralBytes]byte
	copy(e[:], msg1)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Sub(g.pruned) >= time.Minute {
		for k, at := range g.seen {
			if now.Sub(at) >= cloudwire.EarlyDataFor {
				delete(g.seen, k)
			}
		}
		g.pruned = now
	}
	if _, ok := g.seen[e]; ok || len(g.seen) >= maxEarlySeen {
		return false
	}
	g.seen[e] = now
	return true
}

// remember records msg1 without asking, for a message 1 that came once the
// handshake was done on a connection that used early data: a copy of its
// first flight could still be replayed.
func (g *earlyGuard) remember(msg1 []byte) {
	if len(msg1) < ephemeralBytes {
		return
	}
	var e [ephemeralBytes]byte
	copy(e[:], msg1)
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.seen) < maxEarlySeen {
		g.seen[e] = g.now()
	}
}
