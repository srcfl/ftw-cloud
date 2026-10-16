package quicdoor

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

func stamp(at time.Time) []byte {
	return binary.BigEndian.AppendUint64(append([]byte{}, earlyTag...), uint64(at.Unix()))
}

// A ticket allows early data for a day after it was issued, and never one
// without the door's stamp or with a stamp from the future.
func TestATicketAllowsEarlyDataForADay(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	for _, c := range []struct {
		name  string
		extra [][]byte
		ok    bool
	}{
		{"fresh", [][]byte{[]byte("quic-go's own"), stamp(now.Add(-time.Hour))}, true},
		{"a day old", [][]byte{stamp(now.Add(-cloudwire.EarlyDataFor))}, false},
		{"no stamp", [][]byte{[]byte("quic-go's own")}, false},
		{"from the future", [][]byte{stamp(now.Add(time.Hour))}, false},
		{"cut short", [][]byte{stamp(now)[:len(earlyTag)+4]}, false},
	} {
		if got := earlyStillAllowed(c.extra, now); got != c.ok {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// Each message 1 passes once by its ephemeral key, for as long as a ticket
// allows early data.
func TestTheGuardLetsEachMessage1ThroughOnce(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	g := newEarlyGuard(func() time.Time { return now })
	m1 := append(bytes.Repeat([]byte{1}, ephemeralBytes), []byte("the rest of message 1")...)
	if !g.first(m1) {
		t.Fatal("the first copy was refused")
	}
	again := append(bytes.Repeat([]byte{1}, ephemeralBytes), []byte("other bytes, same key")...)
	if g.first(again) {
		t.Fatal("a second copy with the same ephemeral key passed")
	}
	if g.first(m1[:ephemeralBytes-1]) {
		t.Fatal("a message too short to be message 1 passed")
	}
	other := bytes.Repeat([]byte{2}, ephemeralBytes)
	g.remember(other)
	if g.first(other) {
		t.Fatal("a remembered message 1 passed in early data")
	}
	now = now.Add(cloudwire.EarlyDataFor + time.Minute)
	if !g.first(m1) {
		t.Fatal("past a ticket's early-data life the key was still held")
	}
}

func TestEarlyDataIsOnUnderTheGuard(t *testing.T) {
	if !Config().Allow0RTT {
		t.Fatal("0-RTT is off")
	}
}
