// Package appsession serves /v1/app, where a phone reads its home.
// docs/protocol-cloud.md in srcfl/ftw is the wire format ("App session");
// go/protocol/cloudwire holds its bytes.
//
// The phone runs Noise IK as initiator with the service's Noise key as the
// responder's static key and the home id in the prologue. The service admits
// the phone only through store.For with the key the handshake authenticated,
// so a phone reaches only a home whose box listed it in a signed roster.
// Message 2 carries the snapshot; after it every envelope the box sends that
// the device may read goes out unchanged, one frame per Noise message.
//
// A phone may ask for faster updates, ask for its extension token, register
// for alerts, and an owner may suspend a device. Its own Noise session with
// the box rides here as tun, which the service forwards under the device id
// its handshake proved and can neither read nor forge. That is all it can
// do here.
package appsession

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/wire"
	"github.com/srcfl/ftw-cloud/internal/wsclose"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	// maxPhoneMessage bounds one message from a phone: a tun around the
	// largest bulk frame. Every other message must fit maxPlainMessage.
	maxPhoneMessage = cloudwire.MaxTunFrame + appwire.TransportOverhead
	// maxPlainMessage bounds every phone message but tun. Message 1 with
	// now is about 160 bytes.
	maxPlainMessage = 4 << 10
	// handshakeTimeout bounds message 1.
	handshakeTimeout = 10 * time.Second
	// The same ping, read and write deadlines as the uplink.
	pingEvery    = 15 * time.Second
	readTimeout  = 45 * time.Second
	writeTimeout = 10 * time.Second
	// A phone sends a message when it looks away or back, or when an owner
	// suspends a device. Past this burst at this rate the session closes.
	rateBurst  = 20
	ratePerSec = 2
	// tun counts apart, against the home's limits at the uplink, which drop
	// what is over. A phone that sends twice as fast as those pass is not a
	// phone at work, and its session closes.
	tunBurst  = 480
	tunPerSec = 120
	// maxNoiseMessage is the largest Noise message, handshake or transport.
	maxNoiseMessage = 0xffff
	// WatchRenew is how often the service asks the box again for one-second
	// updates while a phone looks. The box's watch lasts 60 s, so the ask
	// comes before it lapses.
	WatchRenew = 50 * time.Second
	// boxWatchLasts is how long the box keeps one watch in force.
	boxWatchLasts = 60 * time.Second
	// roleOwner is the registry's owner role, as the roster names it.
	// go/protocol does not generate role names yet.
	roleOwner = "owner"
)

// Watcher asks a home's box for one-second updates. The uplink is one.
type Watcher interface {
	Watch(home string)
}

// Tunneler sends a phone's tun to its home's box. The uplink is one. False
// means no box takes it now.
type Tunneler interface {
	Tun(home string, t cloudwire.Tun) bool
}

// Exchanger sends a watch's exchange message to its home's box and returns
// the box's answer. The uplink is one. dev comes from store.For, never from
// the watch. Nil or empty is no answer.
type Exchanger interface {
	Exchange(ctx context.Context, home, dev string, d []byte) []byte
}

// What the app sessions count, summed over all homes.
var (
	appSockets     = metrics.Sockets("app")
	appHandshake   = metrics.Handshake("app")
	onceHandshake  = metrics.Handshake("once")
	envelopeOut    = metrics.Forward("envelope")
	tunUp          = metrics.Forward("tun_up")
	appWrongShard  = metrics.WrongShard("app")
	onceWrongShard = metrics.WrongShard("once")
)

// WebOrigin is the one browser origin the service accepts on /v1/app: the
// web app's. The phone and the box send no Origin.
const WebOrigin = "https://app.ftw.energy"

// Server is the /v1/app handler.
type Server struct {
	store    *store.Store
	registry *registry.Registry
	watcher  Watcher
	key      appwire.KeyPair
	log      *slog.Logger
	now      func() time.Time
	// renewEvery is WatchRenew; tests shorten it.
	renewEvery time.Duration
	// once counts the one-shot reads under way; onceMessage2 bounds their
	// message 2, and onceEphemeral, when set, fixes their ephemeral key.
	// Tests set the last two to replay golden vectors.
	once          onceLimits
	onceMessage2  int
	onceEphemeral *appwire.KeyPair

	// Push keeps the phones' APNs tokens. Nil ignores push.register and
	// push.unregister. Set before serving.
	Push Pusher
	// Tokens issues extension tokens. Nil ignores token.get. Set before
	// serving.
	Tokens Tokens
	// Tunnel carries the phones' sessions to their boxes. Nil answers every
	// tun with its end. Set before serving.
	Tunnel Tunneler
	// Exchange carries the watches' exchanges to their boxes. Nil answers
	// every x with no answer. Set before serving.
	Exchange Exchanger
	// Shards says which homes this instance holds. Nil holds every home.
	// Set before serving.
	Shards *shard.Directory

	// sockets are every phone's socket from its upgrade on, so a drain
	// reaches those still in their handshake. draining is set once Drain
	// starts; restartReason is what its close says.
	sockets       wsclose.Set
	draining      atomic.Bool
	restartReason atomic.Value

	mu      sync.Mutex
	looking map[string]*look
	// watchedUntil is, per home, when the box's watch a one-shot read asked
	// for lapses, so a box that comes back before then is asked again.
	watchedUntil map[string]time.Time
}

// Pusher keeps a device's APNs tokens. push.Service is one. dev and scopes
// come from store.For, never from the phone's message.
type Pusher interface {
	Register(home string, dev cloudwire.Device, scopes []string, r cloudwire.PushRegister) error
	Unregister(home string, dev cloudwire.Device, r cloudwire.PushUnregister) error
}

// Tokens gives a device its extension token. token.Service is one. dev
// comes from store.For, never from the phone's message.
type Tokens interface {
	Issue(home string, dev cloudwire.Device) (cloudwire.Token, error)
	Drop(home, deviceID string) error
}

// look is one home's phones that can see it, and the timer that keeps the
// box's watch in force while there is at least one.
type look struct {
	n     int
	timer *time.Timer
}

// New builds the handler. key is the service's Noise static key; the app
// carries its public half.
func New(st *store.Store, reg *registry.Registry, w Watcher, key appwire.KeyPair, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, registry: reg, watcher: w, key: key, log: log, now: time.Now,
		renewEvery: WatchRenew, looking: map[string]*look{}, watchedUntil: map[string]time.Time{}, onceMessage2: maxNoiseMessage,
		once: onceLimits{homes: map[string]int{}, devices: map[string]*onceDevice{}}}
}

var upgrader = websocket.Upgrader{
	EnableCompression: false,
	// The app sends no Origin. A browser always does, and only the web app's
	// has business here.
	CheckOrigin: func(r *http.Request) bool {
		o := r.Header.Get("Origin")
		return o == "" || o == WebOrigin
	},
	// A phone's socket is idle between messages; it borrows a write buffer
	// only while it writes.
	WriteBufferPool: &sync.Pool{},
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		http.Error(w, "TLS 1.3 only", http.StatusUpgradeRequired)
		return
	}
	home := r.URL.Query().Get(cloudwire.AppHomeParam)
	if !cloudwire.ValidHome(home) {
		http.Error(w, "name a home", http.StatusBadRequest)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.ServeConn(conn, home)
}

// ServeConn runs one phone's session on conn, a WebSocket or QUIC (package
// quicdoor), for home. It closes conn.
func (s *Server) ServeConn(conn wire.Conn, home string) {
	defer conn.Close()
	appSockets.Add(1)
	defer appSockets.Add(-1)
	if !cloudwire.ValidHome(home) {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(cloudwire.CloseProtocol, ""), time.Now().Add(time.Second))
		return
	}
	conn.SetReadLimit(maxPhoneMessage)
	sock := s.sockets.Add(conn)
	defer s.sockets.Remove(sock)
	// Drain sets draining before it takes the set, so a socket it did not
	// see sees draining here.
	if s.draining.Load() {
		reason, _ := s.restartReason.Load().(string)
		sock.Close(cloudwire.CloseRestart, reason)
		sock.AwaitPeer()
		return
	}
	// The close goes before message 1 is read: a browser cannot see the
	// status of a refused upgrade, but every client reads a close. The
	// phone's answer is awaited, so it reads the code rather than a reset.
	if host, ours := s.owner(home); !ours {
		appWrongShard.Inc()
		sock.Close(cloudwire.CloseWrongShard, host)
		sock.AwaitPeer()
		return
	}
	var reading <-chan struct{}
	code, err := s.serve(conn, home, &reading)
	if err != nil {
		s.log.Debug("app session closed", "err", err)
	}
	if code == 0 {
		return
	}
	sock.Close(code, "")
	if reading != nil {
		<-reading // the session's reader takes the phone's answer
	} else {
		sock.AwaitPeer()
	}
}

// owner is the host of the shard that holds home, and whether it is this
// instance.
func (s *Server) owner(home string) (string, bool) {
	if s.Shards == nil {
		return "", true
	}
	return s.Shards.Owner(home)
}

// Sockets is how many phone sockets are open, handshakes included.
func (s *Server) Sockets() int { return s.sockets.Len() }

// Drain closes every phone's socket with cloudwire.CloseRestart and reason,
// the spread in milliseconds, those still in their handshake too, and every
// socket that comes after.
func (s *Server) Drain(reason string) {
	s.restartReason.Store(reason)
	s.draining.Store(true)
	s.sockets.CloseAll(cloudwire.CloseRestart, reason)
}

// WaitClosed waits, at most d, until every phone has answered the drain's
// close or timed out, and returns how many sockets are still open.
func (s *Server) WaitClosed(d time.Duration) int { return s.sockets.WaitEmpty(d) }

var errProtocol = errors.New("appsession: the phone broke the protocol")

// serve runs one session and returns the close code to end it with. Once the
// session's reader runs, reading is set to a channel that closes when it
// stops, and only that reader may read the socket.
func (s *Server) serve(conn wire.Conn, home string, reading *<-chan struct{}) (int, error) {
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	kind, msg1, err := conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	if kind != websocket.BinaryMessage || len(msg1) > maxPlainMessage {
		return cloudwire.CloseProtocol, errProtocol
	}
	hs, err := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: s.key, Prologue: cloudwire.AppPrologue(home)})
	if err != nil {
		return websocket.CloseInternalServerErr, err
	}
	payload, err := hs.ReadMessage(msg1)
	if err != nil {
		// Another service key, or another home in the prologue than in the
		// query. Neither says anything about the home.
		return cloudwire.CloseDenied, err
	}
	now, err := parseNow(payload)
	if err != nil {
		return cloudwire.CloseProtocol, err
	}
	hz := now.Hz

	dev, err := s.store.For(store.Principal{Kind: store.Device, Home: home, DeviceKey: hs.RemoteStatic(), Pair: now.Pair})
	if err != nil {
		return cloudwire.CloseDenied, err
	}
	snap, sess, err := dev.Open()
	switch {
	case errors.Is(err, store.ErrBusy):
		return cloudwire.CloseBusy, err
	case err != nil:
		return cloudwire.CloseDenied, err
	}
	defer sess.Close()

	msg2Payload, rest, err := snapshotPayload(snap, maxNoiseMessage)
	if err != nil {
		return websocket.CloseInternalServerErr, err
	}
	msg2, err := hs.WriteMessage(msg2Payload)
	if err != nil {
		return websocket.CloseInternalServerErr, err
	}
	c := &phoneConn{s: s, conn: conn, dev: dev, home: home, tokens: rateBurst, refilled: s.now(),
		tunTokens: tunBurst, tunAt: s.now(), sess: sess,
		replies: make(chan []byte, 1), quit: make(chan struct{})}
	// Whatever ends this session from here on, the box hears its tunnel end.
	defer c.endTun()
	// The box session's message 1, when it rode in message 1, goes to the
	// box before message 2 goes back: the box's answer then follows message
	// 2 by one leg, and the session is up one round trip after TLS.
	if now.Tun != nil {
		c.tunEarly(*now.Tun)
	}
	if err := c.write(msg2); err != nil {
		return 0, err
	}
	appHandshake.Since(start)
	keys, err := hs.Split()
	if err != nil {
		return websocket.CloseInternalServerErr, err
	}
	c.tr = appwire.NewTransport(keys)
	for _, env := range rest {
		if err := c.forward(env); err != nil {
			return 0, err
		}
	}

	c.setLooking(hz >= cloudwire.HzLooking)
	defer c.stopLooking()
	c.readDone = make(chan struct{})
	*reading = c.readDone
	return c.run(sess)
}

// parseNow reads message 1's payload.
func parseNow(payload []byte) (cloudwire.Now, error) {
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil || env.T != cloudwire.MsgNow {
		return cloudwire.Now{}, errProtocol
	}
	var now cloudwire.Now
	if err := cloudwire.Unmarshal(env.B, &now); err != nil {
		return cloudwire.Now{}, errProtocol
	}
	return now, nil
}

// snapshotPayload is message 2. Envelopes that do not fit in a message 2 of
// at most limit bytes come back as rest, to follow as frames.
func snapshotPayload(snap store.Snapshot, limit int) ([]byte, [][]byte, error) {
	envs := snap.Envelopes
	var rest [][]byte
	for {
		payload, err := cloudwire.SnapshotPayload(envs, snap.LastSeenMs, snap.Online, len(rest))
		if err != nil {
			return nil, nil, err
		}
		if len(payload)+appwire.Message2Overhead <= limit || len(envs) == 0 {
			return payload, rest, nil
		}
		rest = append([][]byte{envs[len(envs)-1]}, rest...)
		envs = envs[:len(envs)-1]
	}
}

// setLooking keeps the box's watch in force while at least one phone of the
// home can see it.
func (s *Server) setLooking(home string, delta int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.looking[home]
	if l == nil {
		l = &look{}
		s.looking[home] = l
	}
	l.n += delta
	switch {
	case l.n > 0 && l.timer == nil:
		// A timer, not a goroutine per home: it renews the watch every
		// renewEvery while this look is the home's.
		var renew func()
		renew = func() {
			s.watcher.Watch(home)
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.looking[home] == l && l.n > 0 {
				l.timer = time.AfterFunc(s.renewEvery, renew)
			}
		}
		l.timer = time.AfterFunc(0, renew)
	case l.n <= 0:
		if l.timer != nil {
			l.timer.Stop()
		}
		delete(s.looking, home)
	}
}

// BoxConnected asks a box that just connected for one-second updates when a
// phone is already looking, or a one-shot read asked for them less than a
// minute ago. The uplink calls it after hello_ok.
func (s *Server) BoxConnected(home string) {
	s.mu.Lock()
	looking := s.looking[home] != nil || s.now().Before(s.watchedUntil[home])
	s.mu.Unlock()
	if looking {
		s.watcher.Watch(home)
	}
}

// watchOnce asks the box for one-second updates for a one-shot read with
// hz 1, as a looking phone does, without making the read wait on the box's
// socket. The box's watch lasts a minute; a box that comes back within it
// is asked again.
func (s *Server) watchOnce(home string) {
	now := s.now()
	s.mu.Lock()
	for h, until := range s.watchedUntil {
		if !now.Before(until) {
			delete(s.watchedUntil, h)
		}
	}
	s.watchedUntil[home] = now.Add(boxWatchLasts)
	s.mu.Unlock()
	go s.watcher.Watch(home)
}

// phoneConn is one phone's session after the handshake.
type phoneConn struct {
	s    *Server
	conn wire.Conn
	tr   *appwire.Transport
	dev  *store.Handle
	home string

	// looking is touched by the read loop and by the session's end.
	lookMu  sync.Mutex
	looking bool
	ended   bool

	tokens   float64
	refilled time.Time
	// tunTokens is the tun bucket, refilled at tunAt.
	tunTokens float64
	tunAt     time.Time

	// replies carries the service's answers from the read loop to the
	// session's goroutine, the only one that writes; quit closes when that
	// goroutine is done.
	replies chan []byte
	quit    chan struct{}
	// readDone closes when the reader stops.
	readDone chan struct{}

	// sess is the store's session; tunSid the box session this phone ran
	// last through the tunnel, when hasTun. Touched by the read loop and,
	// once it is done, by the session's end.
	sess   *store.Session
	tunMu  sync.Mutex
	tunSid uint32
	hasTun bool

	// heard is set by the phone's first transport message, which proves it
	// holds message 2. Until then everything goes on the control stream,
	// behind message 2: over QUIC a datagram could overtake it.
	heard atomic.Bool
}

func (c *phoneConn) setLooking(on bool) {
	c.lookMu.Lock()
	defer c.lookMu.Unlock()
	if c.ended || on == c.looking {
		return
	}
	c.looking = on
	delta := -1
	if on {
		delta = 1
	}
	c.s.setLooking(c.home, delta)
}

// stopLooking ends this phone's part in the watch for good, whatever the
// read loop still delivers.
func (c *phoneConn) stopLooking() {
	c.setLooking(false)
	c.lookMu.Lock()
	c.ended = true
	c.lookMu.Unlock()
}

// write sends one WebSocket message. Only the session's own goroutine
// writes; pings go through WriteControl, which may run beside it.
func (c *phoneConn) write(msg []byte) error { return c.writeAs(websocket.BinaryMessage, msg) }

// writeAs sends one message the way kind says, over QUIC; a WebSocket
// carries every kind as a binary message.
func (c *phoneConn) writeAs(kind int, msg []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return c.conn.WriteMessage(wire.Kind(c.conn, kind), msg)
}

// forward sends one box envelope as the box sent it. An envelope too large
// for a Noise message cannot reach a phone; it is dropped, and the phone sees
// the gap through the next hb.
func (c *phoneConn) forward(env []byte) error { return c.forwardAs(websocket.BinaryMessage, env) }

// forwardAs is forward over the path kind names. Over QUIC an hb, or a live
// without its source table, goes as a datagram: the newest wins, and a
// lost one shows as a gap in the phone's freshness rules.
func (c *phoneConn) forwardAs(kind int, env []byte) error {
	frame, err := cloudwire.EncodeFrame(env)
	if err != nil || len(frame)+appwire.TransportOverhead > maxNoiseMessage {
		return nil
	}
	switch {
	case !c.heard.Load():
		kind = websocket.BinaryMessage
	case kind == websocket.BinaryMessage && wire.Kind(c.conn, wire.Datagram) == wire.Datagram:
		if e, err := cloudwire.DecodeEnvelope(env); err == nil && cloudwire.Datagram(e) {
			kind = wire.Datagram
		}
	}
	msg, err := c.tr.Encrypt(frame)
	if err != nil {
		return err
	}
	return c.writeAs(kind, msg)
}

// run forwards until the store ends the session, the phone leaves or breaks
// the protocol.
func (c *phoneConn) run(sess *store.Session) (int, error) {
	defer close(c.quit)
	type result struct {
		code int
		err  error
	}
	read := make(chan result, 1)
	go func() {
		defer close(c.readDone)
		code, err := c.readLoop()
		read <- result{code, err}
	}()
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		select {
		case out := <-sess.C():
			if err := c.forward(out.Env); err != nil {
				return 0, err
			}
			envelopeOut.Observe(out.Waited())
		case env := <-c.replies:
			if err := c.forward(env); err != nil {
				return 0, err
			}
		case t := <-sess.Tun():
			env, err := cloudwire.Unsigned(cloudwire.MsgTun, t.AppTun)
			if err != nil {
				return 0, err
			}
			kind := websocket.BinaryMessage
			if t.Bulk {
				kind = wire.Bulk
			}
			if err := c.forwardAs(kind, env); err != nil {
				return 0, err
			}
			tunUp.Observe(t.Waited())
		case <-sess.Done():
			return sess.Code(), nil
		case r := <-read:
			// The read loop's own work (a suspension) may have ended this
			// session; the store's reason wins over a plain close.
			select {
			case <-sess.Done():
				return sess.Code(), r.err
			default:
			}
			return r.code, r.err
		case <-ping.C:
			if err := c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				return 0, err
			}
		}
	}
}

func (c *phoneConn) readLoop() (int, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	c.conn.SetPongHandler(func(string) error {
		return c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	})
	for {
		kind, msg, err := c.conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
		if kind != websocket.BinaryMessage {
			return cloudwire.CloseProtocol, errProtocol
		}
		frame, err := c.tr.Decrypt(msg)
		if err != nil {
			return cloudwire.CloseProtocol, err
		}
		c.heard.Store(true)
		if code, err := c.apply(frame); err != nil {
			return code, err
		}
	}
}

// tun forwards the phone's own session to its box, under the device id the
// handshake proved. A device without tun in the roster sends nothing. When
// no box takes it, the phone hears its session ended. A d larger than any
// session message breaks the protocol.
func (c *phoneConn) tun(t cloudwire.AppTun) (int, error) {
	if len(t.D) > cloudwire.TunDataMax {
		return cloudwire.CloseProtocol, errProtocol
	}
	dev := c.dev.Device()
	if !dev.Tun {
		return 0, nil
	}
	c.tunMu.Lock()
	c.tunSid, c.hasTun = t.Sid, len(t.D) > 0
	c.tunMu.Unlock()
	if c.sess != nil && len(t.D) > 0 {
		c.sess.SetSid(t.Sid)
	}
	if c.s.Tunnel != nil && c.s.Tunnel.Tun(c.home, cloudwire.Tun{Dev: dev.ID, Sid: t.Sid, D: t.D}) {
		return 0, nil
	}
	if len(t.D) == 0 {
		return 0, nil
	}
	return 0, c.say(cloudwire.MsgTun, cloudwire.AppTun{Sid: t.Sid})
}

// tunEarly forwards the box session's message 1 that rode in message 1. No
// reply can go yet, so a box that cannot take it is heard about as the end
// of the session, once the stream runs.
func (c *phoneConn) tunEarly(t cloudwire.AppTun) {
	dev := c.dev.Device()
	if !dev.Tun || len(t.D) == 0 || len(t.D) > cloudwire.TunDataMax {
		return
	}
	c.tunMu.Lock()
	c.tunSid, c.hasTun = t.Sid, true
	c.tunMu.Unlock()
	c.sess.SetSid(t.Sid)
	if c.s.Tunnel != nil && c.s.Tunnel.Tun(c.home, cloudwire.Tun{Dev: dev.ID, Sid: t.Sid, D: t.D}) {
		return
	}
	c.sess.Ended(t.Sid)
}

// endTun tells the box that the phone's session through here is over, when
// the app session ends.
func (c *phoneConn) endTun() {
	c.tunMu.Lock()
	sid, had := c.tunSid, c.hasTun
	c.hasTun = false
	c.tunMu.Unlock()
	if had && c.s.Tunnel != nil {
		c.s.Tunnel.Tun(c.home, cloudwire.Tun{Dev: c.dev.Device().ID, Sid: sid})
	}
}

// apply acts on one message from the phone. Types it does not know are
// ignored, so a newer app works with an older service.
func (c *phoneConn) apply(frame []byte) (int, error) {
	payload, err := cloudwire.DecodeFrame(frame)
	if err != nil {
		return cloudwire.CloseProtocol, err
	}
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil {
		return cloudwire.CloseProtocol, err
	}
	if env.T == cloudwire.MsgTun {
		now := c.s.now()
		c.tunTokens = min(tunBurst, c.tunTokens+now.Sub(c.tunAt).Seconds()*tunPerSec)
		c.tunAt = now
		if c.tunTokens < 1 {
			return cloudwire.CloseProtocol, errProtocol
		}
		c.tunTokens--
		var t cloudwire.AppTun
		if err := cloudwire.Unmarshal(env.B, &t); err != nil {
			return cloudwire.CloseProtocol, err
		}
		return c.tun(t)
	}
	// tun has limits of its own, per home; everything else counts here.
	if len(frame) > maxPlainMessage || !c.allow() {
		return cloudwire.CloseProtocol, errProtocol
	}
	switch env.T {
	case cloudwire.MsgWatch:
		var w cloudwire.Watch
		if err := cloudwire.Unmarshal(env.B, &w); err != nil {
			return cloudwire.CloseProtocol, err
		}
		c.setLooking(w.Hz >= cloudwire.HzLooking)
	case cloudwire.MsgSuspend, cloudwire.MsgUnsuspend:
		var sus cloudwire.Suspend
		if err := cloudwire.Unmarshal(env.B, &sus); err != nil {
			return cloudwire.CloseProtocol, err
		}
		return 0, c.suspend(sus.DeviceID, env.T == cloudwire.MsgSuspend)
	case cloudwire.MsgPushRegister:
		var r cloudwire.PushRegister
		if err := cloudwire.Unmarshal(env.B, &r); err != nil {
			return cloudwire.CloseProtocol, err
		}
		if c.s.Push != nil {
			return 0, pushed(c.s.Push.Register(c.home, c.dev.Device(), c.dev.Scopes(), r))
		}
	case cloudwire.MsgPushUnregister:
		var r cloudwire.PushUnregister
		if err := cloudwire.Unmarshal(env.B, &r); err != nil {
			return cloudwire.CloseProtocol, err
		}
		if c.s.Push != nil {
			return 0, pushed(c.s.Push.Unregister(c.home, c.dev.Device(), r))
		}
	case cloudwire.MsgTokenGet:
		if c.s.Tokens == nil {
			return 0, nil
		}
		tok, err := c.s.Tokens.Issue(c.home, c.dev.Device())
		if err != nil {
			return 0, err
		}
		return 0, c.say(cloudwire.MsgToken, tok)
	}
	return 0, nil
}

// say hands an answer to the session's goroutine to send.
func (c *phoneConn) say(t string, body any) error {
	env, err := cloudwire.Unsigned(t, body)
	if err != nil {
		return err
	}
	select {
	case c.replies <- env:
		return nil
	case <-c.quit:
		return errClosed
	}
}

var errClosed = errors.New("appsession: the session ended")

// pushed lets the session go on after a registration the device may not
// make, such as a viewer's: it gets no alerts, and nothing else changes.
func pushed(err error) error {
	if errors.Is(err, push.ErrNotForThisDevice) {
		return nil
	}
	return err
}

// suspend applies an owner's suspension or lifts one. It only narrows what
// the roster allows: the device must be in the roster, and lifting a
// suspension gives back no more than the roster says.
func (c *phoneConn) suspend(deviceID string, on bool) error {
	if c.dev.Device().Role != roleOwner {
		return nil
	}
	r, _ := c.dev.Roster()
	if r == nil {
		return nil
	}
	for _, d := range r.Devices {
		if d.ID != deviceID {
			continue
		}
		if !on {
			return c.s.registry.Unsuspend(c.home, d.ID)
		}
		if err := c.s.registry.Suspend(c.home, d.ID, d.Epoch, c.s.now()); err != nil {
			return err
		}
		// The suspended device's sessions end first, whatever happens to
		// its token. Its token dies; lifting the suspension does not bring
		// it back, the app asks for a new one.
		c.dev.Recheck()
		if c.s.Tokens != nil {
			return c.s.Tokens.Drop(c.home, d.ID)
		}
		return nil
	}
	return nil
}

// allow is a token bucket over the phone's messages.
func (c *phoneConn) allow() bool {
	now := c.s.now()
	c.tokens = min(rateBurst, c.tokens+now.Sub(c.refilled).Seconds()*ratePerSec)
	c.refilled = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}
