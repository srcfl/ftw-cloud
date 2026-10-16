package quicdoor

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Early data (srcfl/ftw docs/protocol-cloud.md, "Early data"). The network can
// replay a client's first flight, and quic-go accepts what it carries. These
// rules make a replay change nothing:
//
//   - A session ticket allows early data for cloudwire.EarlyDataFor after it
//     was issued, and resumption without early data after that.
//   - A phone's session waits for the handshake (Door.session), which the
//     sender of a replay cannot finish.
//   - A box sends only its target in early data, and the challenge it may
//     get back changes nothing.
//   - HTTP/3 requests wait for the handshake.

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
