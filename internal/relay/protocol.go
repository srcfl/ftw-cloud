// The command path's wire contract, copied from srcfl/ftw-webapp
// relay/src/protocol.ts and relay/src/epoch.ts.
//
// The box, the webapp and a watch already speak this. They switch hosts by
// changing the origin and nothing else, so these numbers are not ours to
// improve. relay_test.go holds them against the values those clients
// duplicate.
package relay

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// CloseBadJoin is a malformed join, text on a binary channel, or an
	// oversize message.
	CloseBadJoin = 4400
	// CloseEpoch is a join that named the wrong hour. The reason is the
	// right epoch, and nothing else.
	CloseEpoch = 4409
	// CloseRotated is the hour turning. The reason is the new epoch.
	CloseRotated = 4410
	// CloseBusy is a rate limit, a full room, or the process ceiling.
	CloseBusy = 4429

	// CtrlReady means the other side of the room is here.
	CtrlReady = "ready"
	// CtrlGone means it left. The socket stays up.
	CtrlGone = "gone"

	// HandleChars is a rendezvous handle: 128 bits, lowercase hex.
	HandleChars = 32
	// EpochMs is how long one handle lives. An hour.
	EpochMs = 3_600_000

	// ExchangeIDBytes is the id this service draws in front of a watch's
	// request. The box copies it back in front of the answer. It names
	// nothing outside this process.
	ExchangeIDBytes = 16
)

const (
	roleBox      = "box"
	roleApp      = "app"
	roleExchange = "exchange"

	// rotateSpread is how long an hour's turn is spread over, so rooms do
	// not all reconnect on the same second.
	rotateSpread = 5 * time.Minute

	maxStreamsPerRoom = 4
	maxSockets        = 4096
	maxSocketsPerAddr = 16
	maxFrameBytes     = 64 << 10
	maxBufferedWrite  = 10 * time.Second
	heartbeatEvery    = 15 * time.Second
	frameCapacity     = 240
	framesPerSecond   = 60
	byteCapacity      = 4 << 20
	bytesPerSecond    = 512 << 10
	attemptLimit      = 30
	attemptWindow     = time.Minute
	attemptSlots      = 1024

	// Exchange sizes, from docs/watch-exchange.md. Message 1 is 608 bytes
	// and one transport message is 536. Nothing else is a request.
	exchangeOpenBytes    = 608
	exchangeRequestBytes = 536
	exchangeMaxReply     = 4096
	exchangePerMinute    = 30
	exchangeOpenPerRoom  = 2
	exchangeOpenProcess  = 1024
	exchangeTimeout      = 10 * time.Second
)

// CurrentEpoch is the hour the service is in. Peers guess from their own
// clocks and put the guess in the path; a wrong guess is answered with this
// number in the close reason.
func CurrentEpoch(now time.Time) int64 {
	ms := now.UnixMilli()
	// Floor, matching the app's Math.floor. Go divides toward zero, and a
	// clock before 1970 would otherwise disagree with every client.
	if ms < 0 {
		return -((-ms + EpochMs - 1) / EpochMs)
	}
	return ms / EpochMs
}

// RotationOffset is where in the spread this room's turn falls. It comes
// from the handle, so it needs no timer and two rooms do not share a turn
// by waiting for the same tick.
func RotationOffset(handle string, spread time.Duration) time.Duration {
	if len(handle) < 4 || spread <= 0 {
		return 0
	}
	bucket, err := strconv.ParseUint(handle[:4], 16, 16)
	if err != nil {
		return 0
	}
	return time.Duration(float64(spread) * (float64(bucket) / 0x10000))
}

type join struct {
	epoch  int64
	handle string
	role   string
}

// parseJoin reads `/r/<epoch>/<handle>/<box|app|exchange>` and nothing else.
func parseJoin(path string) (join, bool) {
	parts := splitPath(path)
	if len(parts) != 4 || parts[0] != "r" {
		return join{}, false
	}
	epoch, ok := parseEpoch(parts[1])
	if !ok || !handleOK(parts[2]) {
		return join{}, false
	}
	switch parts[3] {
	case roleBox, roleApp, roleExchange:
	default:
		return join{}, false
	}
	return join{epoch: epoch, handle: parts[2], role: parts[3]}, true
}

type exchangeTarget struct {
	epoch  int64
	handle string
}

// parseExchange reads `/x/<epoch>/<handle>` and nothing else.
func parseExchange(path string) (exchangeTarget, bool) {
	parts := splitPath(path)
	if len(parts) != 3 || parts[0] != "x" {
		return exchangeTarget{}, false
	}
	epoch, ok := parseEpoch(parts[1])
	if !ok || !handleOK(parts[2]) {
		return exchangeTarget{}, false
	}
	return exchangeTarget{epoch: epoch, handle: parts[2]}, true
}

func splitPath(path string) []string {
	raw := strings.Split(path, "/")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseEpoch(s string) (int64, bool) {
	// Reject a sign and leading junk. ParseInt accepts "+1" and the
	// clients' own check does not treat that as an epoch.
	if s == "" || s[0] < '0' || s[0] > '9' {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func handleOK(s string) bool {
	if len(s) != HandleChars {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// clientIP is the address a limit is counted against. The port is not part
// of it: every connection has a new port, and a limit that included it
// would never see the same caller twice.
//
// The forwarded header is ignored unless trust is set. ftwcloudd ends TLS
// itself, so nothing trusted sits in front and the header is a value the
// client chooses. trust exists so the test can show that choice.
func clientIP(r *http.Request, trust bool) string {
	if trust {
		if chain := r.Header.Get("X-Forwarded-For"); chain != "" {
			parts := strings.Split(chain, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
