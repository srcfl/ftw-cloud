// Package uplink serves /v1/box, where each linked box keeps one
// connection. docs/protocol-cloud.md in srcfl/ftw is the wire format;
// go/protocol/cloudwire holds its bytes.
//
// The service learns a home only from its box: the home id is a hash of the
// key that signed hello on this TLS session, never a field anyone sends, and
// every message after it but tun must carry that key's signature. tun is a
// phone's own Noise session with the box, which the service routes by device
// and never reads. What the service may say back is the closed set in
// downlink.go.
package uplink

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/wire"
	"github.com/srcfl/ftw-cloud/internal/wsclose"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	// maxBoxFrame bounds one message from a box. A roster for many phones
	// is the largest thing a box sends.
	maxBoxFrame = 64 << 10
	// handshakeTimeout bounds the hello.
	handshakeTimeout = 15 * time.Second
	// pingEvery and readTimeout: the box's read deadline is three pings,
	// and the service gives the box as long.
	pingEvery   = 15 * time.Second
	readTimeout = 45 * time.Second
	// writeTimeout: a write blocked this long is a dead socket.
	writeTimeout = 10 * time.Second
	// A box sends a few messages a second at most. Past the burst at this
	// rate the connection closes; one home cannot occupy the service. tun
	// is counted apart.
	rateBurst  = 60
	ratePerSec = 10
	// tun per home and direction, the limits the relay puts on a box's
	// uplink, shared with the box, which paces its bulk under them. Past
	// them the service drops tun and counts the drop; Noise transport
	// survives a lost message.
	tunMsgBurst   = cloudwire.TunMsgBurst
	tunMsgPerSec  = cloudwire.TunMsgsPerSecond
	tunByteBurst  = cloudwire.TunByteBurst
	tunBytePerSec = cloudwire.TunBytesPerSecond
	// maxPending bounds the pairing codes one roster may list, and
	// maxPendingTTL how long one may last.
	maxPending    = 4
	maxPendingTTL = 3600
	// A box redials after a drop, a deploy or a redirect, a few times an
	// hour. Past connectBurst at one per connectEvery, a home's box is
	// turned away before it touches the registry; its backoff grows.
	connectBurst = 10
	connectEvery = 6 * time.Second
	// limitsIdle is how long a home's limits outlive its last connection,
	// longer than any of its buckets takes to fill again.
	limitsIdle = 2 * time.Minute
	// drainWait bounds Drain's wait for the boxes' answers to its close.
	drainWait = 2 * time.Second
)

// What the uplink counts, summed over all homes.
var (
	boxSockets    = metrics.Sockets("box")
	boxHandshake  = metrics.Handshake("box")
	tunDown       = metrics.Forward("tun_down")
	wrongShard    = metrics.WrongShard("box")
	tunFramesUp   = metrics.Default.Counter("ftwcloud_tun_frames_total", "tun messages forwarded, up from boxes and down to them.", "dir", "up")
	tunFramesDown = metrics.Default.Counter("ftwcloud_tun_frames_total", "tun messages forwarded, up from boxes and down to them.", "dir", "down")
	tunBytesUp    = metrics.Default.Counter("ftwcloud_tun_bytes_total", "Bytes of tun d forwarded, up from boxes and down to them.", "dir", "up")
	tunBytesDown  = metrics.Default.Counter("ftwcloud_tun_bytes_total", "Bytes of tun d forwarded, up from boxes and down to them.", "dir", "down")
	dropTunUp     = metrics.Drop("tun_rate_up")
	dropTunDown   = metrics.Drop("tun_rate_down")
	dropUnknown   = metrics.Drop("box_unknown_type")
	dropConnect   = metrics.Drop("box_connect_rate")
	boxesFollow   = metrics.Default.Gauge("ftwcloud_boxes_following_shards", "Connected boxes that list shard in hello.caps.")
)

// TunDropped is the tun messages dropped past a home's limits, both ways,
// since the process started.
func TunDropped() int64 { return dropTunUp.Load() + dropTunDown.Load() }

// Uplink is the /v1/box handler.
type Uplink struct {
	// Statistics is set before serving, after the consent tables exist.
	Statistics      bool
	StatisticsStore bool
	store           *store.Store
	registry        *registry.Registry
	key             *ecdsa.PrivateKey
	log             *slog.Logger
	now             func() time.Time

	mu    sync.Mutex
	conns map[string]*boxConn
	// limits are each home's rate limits, kept across its connections.
	limits map[string]*limits

	// Shards says which homes this instance holds. Nil holds every home.
	// Set before serving.
	Shards *shard.Directory
	// sockets are every box's socket from its upgrade on, so a drain
	// reaches those still in their handshake. draining is set once Drain
	// starts; restartReason is what its close says.
	sockets       wsclose.Set
	draining      atomic.Bool
	restartReason atomic.Value

	// OnConnect runs after a box's hello_ok, so the app sessions can ask a
	// box that just came back for one-second updates and push can stop
	// waiting to say it is out of reach. conn, here and in OnGone, is the
	// home's connection number, which rises with each connection, so a
	// hook heard late can be told from a newer one. Set before serving.
	OnConnect func(home string, conn uint64)
	// OnHeld gets each envelope the service holds, with its class, as the
	// box signed it; OnRoster each roster the service keeps; OnGone the end
	// of the home's current uplink, with the reason the box gave in its
	// bye, or "" when the socket just dropped. Push uses them. Each runs on
	// the box's goroutine and must not block. Set before serving.
	OnHeld   func(home, class string, envelope []byte)
	OnRoster func(home string, r *cloudwire.Roster)
	OnGone   func(home, why string, conn uint64)
	// OnNotice gets each security notice, as the box signed it, with the
	// readable copy on or off. The service holds none. It runs on the
	// box's goroutine and must not block. Set before serving.
	OnNotice func(home string, envelope []byte)
	// OnPurge hears that a box purged its home, each time it asks, so what
	// other parts keep for the home goes with it. It runs on the box's
	// goroutine and must not block. Set before serving.
	OnPurge func(home string)
}

// New builds the handler. key is the service key that signs hello_ok and
// purged; boxes carry its public half.
func New(st *store.Store, reg *registry.Registry, key *ecdsa.PrivateKey, log *slog.Logger) *Uplink {
	if log == nil {
		log = slog.Default()
	}
	return &Uplink{store: st, registry: reg, key: key, log: log, now: time.Now, conns: map[string]*boxConn{},
		limits: map[string]*limits{}}
}

// limits are one home's rate limits. They outlive the connection, so a box
// that redials does not start again with full buckets.
type limits struct {
	mu sync.Mutex
	// msgs counts the box's signed messages; connects its connections.
	msgs, connects bucket
	// The tunnel's limits: up from the box, down from the home's phones.
	// upHard is twice the up limits: a box past it is not pacing its
	// tunnel, and its uplink closes.
	upMsgs, upBytes         bucket
	upHardMsgs, upHardBytes bucket
	downMsgs, downBytes     bucket
	// conns is how many connections use these now, and idle since when
	// none has.
	conns int
	idle  time.Time
}

func newLimits(now time.Time) *limits {
	return &limits{
		msgs: newBucket(rateBurst, ratePerSec, now), connects: newBucket(connectBurst, 1/connectEvery.Seconds(), now),
		upMsgs: newBucket(tunMsgBurst, tunMsgPerSec, now), upBytes: newBucket(tunByteBurst, tunBytePerSec, now),
		upHardMsgs: newBucket(2*tunMsgBurst, 2*tunMsgPerSec, now), upHardBytes: newBucket(2*tunByteBurst, 2*tunBytePerSec, now),
		downMsgs: newBucket(tunMsgBurst, tunMsgPerSec, now), downBytes: newBucket(tunByteBurst, tunBytePerSec, now),
	}
}

// take runs f on the limits under their lock.
func (l *limits) take(f func() bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return f()
}

// limitsFor returns a home's limits and counts one more connection on them.
func (u *Uplink) limitsFor(home string) *limits {
	u.mu.Lock()
	defer u.mu.Unlock()
	l := u.limits[home]
	if l == nil {
		l = newLimits(u.now())
		u.limits[home] = l
	}
	l.conns++
	return l
}

// release counts one connection fewer on a home's limits.
func (u *Uplink) release(l *limits) {
	u.mu.Lock()
	defer u.mu.Unlock()
	l.conns--
	if l.conns == 0 {
		l.idle = u.now()
	}
}

// Sweep forgets the limits of homes whose box has been gone for longer than
// any bucket takes to fill. Upkeep calls it.
func (u *Uplink) Sweep() {
	now := u.now()
	u.mu.Lock()
	defer u.mu.Unlock()
	for home, l := range u.limits {
		if l.conns == 0 && now.Sub(l.idle) > limitsIdle {
			delete(u.limits, home)
		}
	}
}

// Boxes is how many boxes are connected now.
func (u *Uplink) Boxes() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.conns)
}

// Sockets is how many box sockets are open, handshakes included.
func (u *Uplink) Sockets() int { return u.sockets.Len() }

// Drain closes every box's socket with cloudwire.CloseRestart and reason,
// the spread in milliseconds, those still in their handshake too, and turns
// away any that come after. Their absence starts no box.unreachable: the
// service is the one going.
func (u *Uplink) Drain(reason string) {
	u.restartReason.Store(reason)
	u.draining.Store(true)
	u.sockets.CloseAll(cloudwire.CloseRestart, reason)
}

// WaitClosed waits, at most d, until every box has answered the drain's
// close or timed out, and returns how many sockets are still open.
func (u *Uplink) WaitClosed(d time.Duration) int { return u.sockets.WaitEmpty(d) }

// owner is the host of the shard that holds home, and whether it is this
// instance.
func (u *Uplink) owner(home string) (string, bool) {
	if u.Shards == nil {
		return "", true
	}
	return u.Shards.Owner(home)
}

var upgrader = websocket.Upgrader{
	EnableCompression: false,
	// A box sends no Origin. A browser always does, and has no business
	// here.
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
	// A box's socket is idle between messages; it borrows a write buffer
	// only while it writes.
	WriteBufferPool: &sync.Pool{},
}

func (u *Uplink) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		http.Error(w, "TLS 1.3 only", http.StatusUpgradeRequired)
		return
	}
	// The handshake is bound to this TLS session. A proxy that ended TLS
	// in front of the service would hold another session with another
	// value, and the box's check fails there.
	ekm, err := r.TLS.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
	if err != nil {
		http.Error(w, "no exporter", http.StatusInternalServerError)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	u.ServeConn(conn, ekm)
}

// ServeConn serves one box's uplink on conn, a WebSocket or QUIC (package
// quicdoor). ekm is the exporter of the TLS session conn rides on, which the
// box's hello must carry. It closes conn.
func (u *Uplink) ServeConn(conn wire.Conn, ekm []byte) {
	defer conn.Close()
	conn.SetReadLimit(maxBoxFrame)
	boxSockets.Add(1)
	defer boxSockets.Add(-1)
	sock := u.sockets.Add(conn)
	defer u.sockets.Remove(sock)
	c := &boxConn{u: u, conn: conn, sock: sock, ekm: ekm, started: time.Now()}
	c.write = c.writeFrame
	// Drain sets draining before it takes the set, so a socket it did not
	// see sees draining here.
	if u.draining.Load() {
		reason, _ := u.restartReason.Load().(string)
		c.closeAndWait(cloudwire.CloseRestart, reason)
		return
	}
	if err := c.run(); err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		u.log.Debug("box uplink closed", "err", err)
	}
}

// Watch asks a home's box for one-second updates for a minute. The app
// sessions call it while a phone is looking.
func (u *Uplink) Watch(home string) {
	u.mu.Lock()
	c := u.conns[home]
	u.mu.Unlock()
	if c != nil {
		_ = c.send(watch{Hz: 1})
	}
}

// Tun sends a phone's tun to its home's box. t.Dev is the device the app
// session's own handshake matched, never one a phone named. False means no
// box takes it now: none is connected, or it does not take tun. A message
// past the home's limits is dropped and counted, and Tun still says true,
// because the box is there.
func (u *Uplink) Tun(home string, t cloudwire.Tun) bool {
	start := time.Now()
	u.mu.Lock()
	c := u.conns[home]
	u.mu.Unlock()
	if c == nil || !c.tun {
		return false
	}
	now := u.now()
	if !c.lim.take(func() bool { return tunAllowed(&c.lim.downMsgs, &c.lim.downBytes, len(t.D), now) }) {
		dropTunDown.Inc()
		return true
	}
	if c.send(tun(t)) != nil {
		return false
	}
	tunDown.Since(start)
	tunFramesDown.Inc()
	tunBytesDown.Add(int64(len(t.D)))
	return true
}

// Restore holds each home's last signed roster again after a restart, read
// back from the registry, so its phones are admitted before its box has
// reconnected. A roster that does not verify with the home's key is left
// out. The roster's time to live counts from when it first arrived.
func (u *Uplink) Restore() (int, error) {
	homes, err := u.registry.Rosters()
	if err != nil {
		return 0, err
	}
	// Checking a signature is most of the work, so the rosters are checked
	// side by side, one worker per core: a deploy admits phones sooner.
	var n, bad atomic.Int64
	work := make(chan registry.Home)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range work {
				r, ok := verifiedRoster(h)
				if !ok {
					bad.Add(1)
					continue
				}
				u.store.Seed(h.ID, r, h.RosterAt)
				n.Add(1)
			}
		}()
	}
	for _, h := range homes {
		// A home another shard holds now is that shard's to restore.
		if _, ours := u.owner(h.ID); ours {
			work <- h
		}
	}
	close(work)
	wg.Wait()
	if bad.Load() > 0 {
		u.log.Warn("stored rosters that do not verify; their homes wait for their boxes", "count", bad.Load())
	}
	return int(n.Load()), nil
}

// verifiedRoster is a stored roster, if it verifies with its home's key.
func verifiedRoster(h registry.Home) (*cloudwire.Roster, bool) {
	pub, err := cloudwire.ParsePublicKey(h.PK)
	if err != nil || cloudwire.HomeID(h.PK) != h.ID {
		return nil, false
	}
	env, err := cloudwire.DecodeEnvelope(h.Roster)
	if err != nil || env.T != cloudwire.MsgRoster || cloudwire.Verify(pub, h.ID, env) != nil {
		return nil, false
	}
	var r cloudwire.Roster
	if cloudwire.Unmarshal(env.B, &r) != nil {
		return nil, false
	}
	return &r, true
}

// boxConn is one box's connection.
type boxConn struct {
	u    *Uplink
	conn wire.Conn
	ekm  []byte
	// write sends one frame; tests replace it.
	write   func([]byte) error
	writeMu sync.Mutex

	home   string
	pub    *ecdsa.PublicKey
	handle *store.Handle
	purged bool
	// tun is whether the box listed tun in hello.caps. An older box closes
	// the uplink on a type it does not know, so it is sent none.
	tun bool
	// bye is the reason the box gave for leaving, if it gave one.
	bye string
	// sock closes the socket with a code; started is when it was
	// upgraded; lim the home's limits, once hello named the home.
	sock    *wsclose.Socket
	started time.Time
	lim     *limits
	// pinger pings the box every pingEvery until stopped.
	pinger  atomic.Pointer[time.Timer]
	stopped atomic.Bool

	// newest is the highest seq of each newest-wins class on this
	// connection. Over QUIC an hb or a live may come as a datagram, out of
	// order; one older than what the service holds is dropped. tableRev is
	// the srcRev of the newest table held from this connection.
	newest   map[string]uint64
	tableRev uint64
}

// bucket is a token bucket.
type bucket struct {
	tokens, burst, rate float64
	at                  time.Time
}

func newBucket(burst, rate float64, now time.Time) bucket {
	return bucket{tokens: burst, burst: burst, rate: rate, at: now}
}

func (b *bucket) take(n float64, now time.Time) bool {
	b.tokens = min(b.burst, b.tokens+now.Sub(b.at).Seconds()*b.rate)
	b.at = now
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

// tunAllowed takes one message of n bytes from a direction's two buckets.
func tunAllowed(msgs, bytes *bucket, n int, now time.Time) bool {
	if !msgs.take(1, now) {
		return false
	}
	if !bytes.take(float64(n), now) {
		msgs.tokens++
		return false
	}
	return true
}

// writeFrame writes one frame. A write that fails or times out closes the
// socket, so the box's read loop ends and the box redials, rather than
// a socket that can read but never write lingering until its deadline.
func (c *boxConn) writeFrame(frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err == nil {
		err = c.conn.WriteMessage(websocket.BinaryMessage, frame)
	}
	if err != nil {
		_ = c.conn.Close()
	}
	return err
}

// closeAndWait ends the uplink with a close code and reason, and waits for
// the box's answer, so the box reads the code rather than a reset. Only the
// box's own goroutine calls it.
func (c *boxConn) closeAndWait(code int, reason string) {
	c.sock.Close(code, reason)
	c.sock.AwaitPeer()
}

var errProtocol = errors.New("uplink: the box broke the protocol")

func (c *boxConn) run() error {
	nonce := make([]byte, cloudwire.NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := c.send(challenge{V: cloudwire.Version, Nonce: nonce}); err != nil {
		return err
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	kind, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}
	env, err := parseUplink(kind, msg)
	if err != nil {
		return err
	}
	if kind != websocket.BinaryMessage {
		return fmt.Errorf("%w: hello off the control stream", errProtocol)
	}
	hello, err := c.hello(env, nonce)
	if err != nil {
		return err
	}
	// Another shard's home goes there before it touches this registry; a
	// service about to stop sends the box to the next one.
	if host, ours := c.u.owner(c.home); !ours {
		wrongShard.Inc()
		c.closeAndWait(cloudwire.CloseWrongShard, host)
		return nil
	}
	c.lim = c.u.limitsFor(c.home)
	defer c.u.release(c.lim)
	if !c.lim.take(func() bool { return c.lim.connects.take(1, c.u.now()) }) {
		dropConnect.Inc()
		c.closeAndWait(cloudwire.CloseBusy, "")
		return nil
	}

	switch err := c.u.registry.Claim(c.home, hello.PK, c.u.now()); {
	case errors.Is(err, registry.ErrPurged):
		// A box still waiting for its receipt. It may say bye, and get
		// the receipt again; nothing else.
		c.purged = true
	case err != nil:
		return err
	}
	if !c.purged {
		if c.handle, err = c.u.store.For(store.Principal{Kind: store.Box, Home: c.home}); err != nil {
			return err
		}
	}
	statsPolicy := ""
	if c.u.Statistics {
		statsPolicy = cloudwire.StatsPolicy
	}
	if err := c.send(helloOK{StatsPolicy: statsPolicy, BoxNonce: hello.BoxNonce, EKM: c.ekm, Have: map[string]string{}, RosterSeq: c.rosterSeq()}); err != nil {
		return err
	}
	boxHandshake.Since(c.started)
	if slices.Contains(hello.Caps, cloudwire.CapShard) {
		boxesFollow.Add(1)
		defer boxesFollow.Add(-1)
	}
	// The connection becomes the home's only after hello_ok has gone, so a
	// watch or a tun from a phone can never reach the box before it: the
	// box closes on anything else while it waits for hello_ok.
	if !c.purged {
		gen := c.handle.Connected()
		defer c.handle.Disconnected(gen)
		c.u.mu.Lock()
		if old := c.u.conns[c.home]; old != nil {
			// One uplink per home: the newer one wins.
			_ = old.conn.Close()
		}
		c.u.conns[c.home] = c
		c.u.mu.Unlock()
		defer func() {
			c.u.mu.Lock()
			current := c.u.conns[c.home] == c
			if current {
				delete(c.u.conns, c.home)
			}
			c.u.mu.Unlock()
			if current && c.u.OnGone != nil && !c.u.draining.Load() {
				c.u.OnGone(c.home, c.bye, gen)
			}
		}()
		if c.u.OnConnect != nil {
			go c.u.OnConnect(c.home, gen)
		}
	}

	// The ping is a timer, not a goroutine of its own: a box's socket is
	// idle most of the time, and ten thousand idle stacks are memory.
	pinger := time.AfterFunc(pingEvery, c.ping)
	c.pinger.Store(pinger)
	defer func() {
		c.stopped.Store(true)
		pinger.Stop()
	}()
	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	})
	for {
		kind, msg, err := c.conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
		env, err := parseUplink(kind, msg)
		if err != nil {
			return err
		}
		switch {
		case kind == wire.Datagram && !cloudwire.Datagram(env):
			return fmt.Errorf("%w: a %s as a datagram", errProtocol, env.T)
		case kind == wire.Bulk && env.T != cloudwire.MsgTun:
			return fmt.Errorf("%w: a %s on the bulk stream", errProtocol, env.T)
		}
		if env.T == cloudwire.MsgTun && !c.purged {
			if err := c.fromBox(env, kind == wire.Bulk); err != nil {
				return err
			}
			continue
		}
		if !c.allow() {
			return fmt.Errorf("%w: faster than %d messages a second", errProtocol, ratePerSec)
		}
		stop, err := c.apply(env)
		if err != nil || stop {
			return err
		}
	}
}

// hello checks the box's opening message and learns the home from its key.
func (c *boxConn) hello(env cloudwire.Envelope, nonce []byte) (cloudwire.Hello, error) {
	var h cloudwire.Hello
	if env.T != cloudwire.MsgHello || cloudwire.Unmarshal(env.B, &h) != nil || h.V != cloudwire.Version {
		return h, fmt.Errorf("%w: expected hello", errProtocol)
	}
	pub, err := cloudwire.ParsePublicKey(h.PK)
	if err != nil {
		return h, err
	}
	home := cloudwire.HomeID(h.PK)
	if err := cloudwire.Verify(pub, home, env); err != nil {
		return h, err
	}
	if !bytes.Equal(h.Nonce, nonce) || !bytes.Equal(h.EKM, c.ekm) || len(h.BoxNonce) != cloudwire.NonceBytes {
		return h, fmt.Errorf("%w: hello is not bound to this challenge and TLS session", errProtocol)
	}
	c.home, c.pub, c.tun = home, pub, slices.Contains(h.Caps, cloudwire.CapTun)
	return h, nil
}

// fromBox routes one tun from the box to the phone whose session it is. It
// is not signed and never read: d is the phone's and the box's. A phone that
// has gone gets its session ended at the box. bulk is a tun from the box's
// bulk stream, which goes on the phone's.
func (c *boxConn) fromBox(env cloudwire.Envelope, bulk bool) error {
	var t cloudwire.Tun
	if len(env.Sig) != 0 || cloudwire.Unmarshal(env.B, &t) != nil || len(t.D) > cloudwire.TunDataMax || t.Dev == "" {
		return fmt.Errorf("%w: a tun the service cannot route", errProtocol)
	}
	now := c.u.now()
	hard, ok := true, true
	c.lim.take(func() bool {
		hard = tunAllowed(&c.lim.upHardMsgs, &c.lim.upHardBytes, len(t.D), now)
		ok = hard && tunAllowed(&c.lim.upMsgs, &c.lim.upBytes, len(t.D), now)
		return ok
	})
	if !hard {
		return fmt.Errorf("%w: tun at twice the home's limits", errProtocol)
	}
	if !ok {
		dropTunUp.Inc()
		return nil
	}
	tunFramesUp.Inc()
	tunBytesUp.Add(int64(len(t.D)))
	if !c.handle.TunBy(t, bulk) && !t.Ended() && c.tun {
		return c.send(tun{Dev: t.Dev, Sid: t.Sid})
	}
	return nil
}

func (c *boxConn) rosterSeq() uint64 {
	var seq uint64
	if c.handle != nil {
		_, seq = c.handle.Roster()
	}
	if h, ok, err := c.u.registry.Get(c.home); err == nil && ok && h.RosterSeq > seq {
		seq = h.RosterSeq
	}
	return seq
}

// ping sends one ping and sets the next, until the connection ends or a
// ping cannot be written.
func (c *boxConn) ping() {
	if c.stopped.Load() || c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)) != nil {
		return
	}
	if t := c.pinger.Load(); t != nil && !c.stopped.Load() {
		t.Reset(pingEvery)
	}
}

// allow is a token bucket over the box's signed messages, kept with the
// home's limits.
func (c *boxConn) allow() bool {
	now := c.u.now()
	return c.lim.take(func() bool { return c.lim.msgs.take(1, now) })
}

// parseUplink reads one box frame. Only binary lane 1 frames carry the
// protocol, on the control stream, the bulk stream or as a datagram.
func parseUplink(kind int, msg []byte) (cloudwire.Envelope, error) {
	if kind != websocket.BinaryMessage && kind != wire.Bulk && kind != wire.Datagram {
		return cloudwire.Envelope{}, fmt.Errorf("%w: a text message", errProtocol)
	}
	payload, err := cloudwire.DecodeFrame(msg)
	if err != nil {
		return cloudwire.Envelope{}, fmt.Errorf("%w: %v", errProtocol, err)
	}
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil {
		return cloudwire.Envelope{}, fmt.Errorf("%w: %v", errProtocol, err)
	}
	return env, nil
}

// apply acts on one signed message from the box. stop ends the connection.
func (c *boxConn) apply(env cloudwire.Envelope) (stop bool, err error) {
	if err := cloudwire.Verify(c.pub, c.home, env); err != nil {
		return true, err
	}
	var h cloudwire.Header
	if err := cloudwire.Unmarshal(env.B, &h); err != nil {
		return true, err
	}
	if c.purged && env.T != cloudwire.MsgBye {
		return true, fmt.Errorf("%w: %s from a purged home", errProtocol, env.T)
	}

	switch env.T {
	case cloudwire.MsgRoster:
		return false, c.roster(env)
	case cloudwire.MsgStats:
		if !c.u.Statistics {
			return false, nil
		}
		var report cloudwire.Stats
		if err := cloudwire.Unmarshal(env.B, &report); err != nil {
			return true, err
		}
		return false, c.u.registry.StatisticsPut(c.home, report, c.u.now())
	case cloudwire.MsgBye:
		var b cloudwire.Bye
		if err := cloudwire.Unmarshal(env.B, &b); err != nil {
			return true, err
		}
		c.bye = b.Why
		if b.Purge {
			return true, c.purge()
		}
		return true, nil
	case cloudwire.MsgHello:
		return true, fmt.Errorf("%w: a second hello", errProtocol)
	case cloudwire.MsgNotice:
		// For the owners' phones whatever the grant, so not behind
		// Serving(), which is the copy; push checks that it holds a notice
		// and nothing more. A box that has sent no roster names no owner,
		// and its notice costs nothing.
		if r, _ := c.handle.Roster(); r != nil && c.u.OnNotice != nil {
			raw, err := env.Encode()
			if err != nil {
				return true, err
			}
			c.u.OnNotice(c.home, raw)
		}
		return false, nil
	}

	if _, forwarded := cloudwire.ClassScope[env.T]; !forwarded {
		dropUnknown.Inc()
		return false, nil
	}
	if !c.handle.Serving() {
		// The readable copy is off: the service holds no readings.
		return false, nil
	}
	rev, table := uint64(0), false
	if env.T == cloudwire.MsgLive {
		rev, table = tableOf(env.B)
	}
	if !c.newer(env.T, h.Seq) {
		// Over QUIC a live without its table can overtake the one that
		// carries it. The late one still brings a newer table, and nothing
		// else (docs/protocol-cloud.md, "Datagrams").
		if !table || rev <= c.tableRev {
			return false, nil
		}
		raw, err := env.Encode()
		if err != nil {
			return true, err
		}
		c.tableRev = rev
		c.handle.PutTable(raw, h.Seq)
		return false, nil
	}
	raw, err := env.Encode()
	if err != nil {
		return true, err
	}
	if table {
		c.tableRev = max(c.tableRev, rev)
	}
	if err := c.handle.Put(env.T, raw, h.Seq, table); err != nil {
		return true, err
	}
	if c.u.OnHeld != nil {
		c.u.OnHeld(c.home, env.T, raw)
	}
	return false, nil
}

// newer reports whether a message of a newest-wins class is newer than any
// of its class on this connection, and remembers it. Over a WebSocket every
// one is; over QUIC a datagram can arrive after a later message.
func (c *boxConn) newer(t string, seq uint64) bool {
	if t != cloudwire.MsgLive && t != cloudwire.MsgHB {
		return true
	}
	if c.newest == nil {
		c.newest = map[string]uint64{}
	}
	if seq <= c.newest[t] {
		return false
	}
	c.newest[t] = seq
	return true
}

// tableOf reports whether a live body holds its source table, and the
// table's srcRev.
func tableOf(body []byte) (uint64, bool) {
	var l struct {
		Sources map[string]cbor.RawMessage `cbor:"sources"`
		SrcRev  uint64                     `cbor:"srcRev"`
	}
	if cloudwire.Unmarshal(body, &l) != nil || len(l.Sources) == 0 {
		return 0, false
	}
	return l.SrcRev, true
}

// roster keeps a signed roster whose grant and scopes are within what FTW
// Cloud may hold.
func (c *boxConn) roster(env cloudwire.Envelope) error {
	var r cloudwire.Roster
	if err := cloudwire.Unmarshal(env.B, &r); err != nil {
		return err
	}
	within := func(have, allowed []string) bool {
		for _, s := range have {
			if !slices.Contains(allowed, s) {
				return false
			}
		}
		return true
	}
	// A grant has three shapes: a copy with serve, a withdrawn one with its
	// id alone, or none at all.
	if err := cloudwire.ValidateWebPush(r.WebPush); err != nil {
		return fmt.Errorf("%w: browser notice rows", errProtocol)
	}
	g := r.Grant
	on := len(g.ID) == cloudwire.GrantIDBytes && slices.Contains(g.Purposes, protocol.CloudPurposeServe)
	bare := len(g.Scopes) == 0 && len(g.Purposes) == 0
	withdrawn := len(g.ID) == cloudwire.GrantIDBytes && bare
	if !(on || withdrawn || (len(g.ID) == 0 && bare)) || g.Controller == "" || r.TTLS <= 0 ||
		!within(g.Scopes, protocol.CloudScopes) || !within(g.Purposes, protocol.CloudPurposes) {
		return fmt.Errorf("%w: a roster outside what FTW Cloud may hold", errProtocol)
	}
	for _, d := range r.Devices {
		if len(d.Key) != 32 || d.ID == "" || !within(d.Scopes, protocol.CloudScopes) {
			return fmt.Errorf("%w: a roster device the service cannot use", errProtocol)
		}
	}
	if len(r.Pending) > maxPending {
		return fmt.Errorf("%w: %d pairing codes in one roster", errProtocol, len(r.Pending))
	}
	for _, p := range r.Pending {
		if len(p.Hash) != cloudwire.PairingHashBytes || p.TTLS <= 0 || p.TTLS > maxPendingTTL {
			return fmt.Errorf("%w: a pairing code the service cannot hold", errProtocol)
		}
	}
	if !c.handle.SetRoster(&r) {
		return nil // older than what is held: ignored
	}
	if c.u.Statistics || c.u.StatisticsStore {
		if err := c.u.registry.StatisticsGrant(c.home, g); err != nil {
			return err
		}
	}
	if withdrawn {
		if err := c.dropCopy(g.ID); err != nil {
			return err
		}
	}
	if c.u.OnRoster != nil {
		c.u.OnRoster(c.home, &r)
	}
	raw, err := env.Encode()
	if err != nil {
		return err
	}
	if err := c.u.registry.SetRoster(c.home, r.RosterSeq, r.Grant.ID, raw, c.u.now()); err != nil {
		return err
	}
	// A device the roster dropped, or whose epoch moved, is no longer
	// suspended: it is gone, or paired again.
	epochs := make(map[string]uint64, len(r.Devices))
	for _, d := range r.Devices {
		epochs[d.ID] = d.Epoch
	}
	return c.u.registry.PruneSuspensions(c.home, epochs)
}

// dropCopy deletes what the service holds under a grant its owner withdrew,
// the readings and the extension tokens that read them, and sends the signed
// receipt. The home, its roster and its tunnel stay. A roster that names the
// same withdrawn grant again gets the receipt again.
func (c *boxConn) dropCopy(grantID []byte) error {
	c.handle.DropCopy()
	if err := c.u.registry.TokenPrune(c.home, func(string, uint64) bool { return false }); err != nil {
		return err
	}
	c.u.log.Info("a home's readable copy deleted at its box's request")
	return c.send(purged{AtMs: c.u.now().UnixMilli(), What: cloudwire.PurgedCopy, GrantID: grantID})
}

// purge deletes the home and sends the signed receipt. For a home already
// purged, the receipt goes again.
func (c *boxConn) purge() error {
	now := c.u.now()
	var grantID []byte
	if c.handle != nil {
		if r, _ := c.handle.Roster(); r != nil {
			grantID = r.Grant.ID
		}
	}
	if h, ok, err := c.u.registry.Get(c.home); err == nil && ok && grantID == nil {
		grantID = h.GrantID
	}
	if !c.purged {
		if err := c.u.registry.Purge(c.home, grantID, now); err != nil {
			return err
		}
		c.handle.Delete()
		c.u.log.Info("home purged at its box's request")
	} else if grantID == nil {
		grantID = c.u.registry.TombstoneGrant(c.home)
	}
	if c.u.OnPurge != nil {
		c.u.OnPurge(c.home)
	}
	return c.send(purged{AtMs: now.UnixMilli(), What: cloudwire.PurgedHome, GrantID: grantID})
}
