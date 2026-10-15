package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// bucket is a per-socket allowance. It lives on the socket and dies with
// it, so a closed connection leaves no keyed record.
type bucket struct {
	tokens   float64
	capacity float64
	perSec   float64
	last     time.Time
}

func newBucket(capacity, perSec float64, now time.Time) *bucket {
	return &bucket{tokens: capacity, capacity: capacity, perSec: perSec, last: now}
}

// take reports whether cost was affordable. A false means the caller is over
// and the connection should close: dropping one frame would leave a hole in
// a stream the session above would have to recover from anyway.
func (b *bucket) take(cost float64, now time.Time) bool {
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.perSec
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}
	b.last = now
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

// attempts counts connection attempts per window without keeping addresses.
//
// The counts sit in a fixed array indexed by a keyed hash. The key is drawn
// at the start of each window and thrown away with the counts, so the array
// cannot be turned back into a list of who connected. Slots collide, and a
// heavy caller then shares a limit with whoever hashed beside them.
type attempts struct {
	limit  int
	window time.Duration
	counts []uint16
	key    []byte
	ends   time.Time
}

func newAttempts(limit int, window time.Duration, slots int, now time.Time) *attempts {
	a := &attempts{limit: limit, window: window, counts: make([]uint16, slots)}
	a.roll(now)
	return a
}

func (a *attempts) allow(addr string, now time.Time) bool {
	if !now.Before(a.ends) {
		a.roll(now)
	}
	slot := a.slot(addr)
	if int(a.counts[slot]) >= a.limit {
		return false
	}
	a.counts[slot]++
	return true
}

func (a *attempts) roll(now time.Time) {
	clear(a.counts)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	a.key = key
	a.ends = now.Add(a.window)
}

func (a *attempts) slot(addr string) int {
	mac := hmac.New(sha256.New, a.key)
	_, _ = mac.Write([]byte(addr))
	sum := mac.Sum(nil)
	return int(binary.BigEndian.Uint32(sum[:4]) % uint32(len(a.counts)))
}
