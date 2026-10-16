package quicdoor

import (
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

func TestEarlyDataIsOn(t *testing.T) {
	if !Config().Allow0RTT {
		t.Fatal("0-RTT is off")
	}
}
