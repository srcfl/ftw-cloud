// Package uplink serves /v1/box, where each box that has turned FTW Cloud on
// keeps one connection. docs/protocol-cloud.md in srcfl/ftw is the wire
// format; go/protocol/cloudwire holds its bytes.
//
// The service learns a home only from its box: the home id is a hash of the
// key that signed hello on this TLS session, never a field anyone sends, and
// every message after it must carry that key's signature. What the service
// may say back is the closed set in downlink.go.
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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
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
	// rate the connection closes; one home cannot occupy the service.
	rateBurst  = 60
	ratePerSec = 10
)

// Uplink is the /v1/box handler.
type Uplink struct {
	store    *store.Store
	registry *registry.Registry
	key      *ecdsa.PrivateKey
	log      *slog.Logger
	now      func() time.Time

	mu    sync.Mutex
	conns map[string]*boxConn

	// Dropped counts box messages of a type this service does not know. A
	// newer box works with an older service by this rule.
	Dropped atomic.Int64

	// OnConnect runs after a box's hello_ok, so the app sessions can ask a
	// box that just came back for one-second updates. Set before serving.
	OnConnect func(home string)
	// OnEvent gets each event the box signed, as the envelope it arrived
	// in; OnRoster each roster the service keeps; OnGone the end of the
	// home's current uplink, with the reason the box gave in its bye, or
	// "" when the socket just dropped. Push uses them. Each runs on the
	// box's goroutine and must not block. Set before serving.
	OnEvent  func(home string, envelope []byte)
	OnRoster func(home string, r *cloudwire.Roster)
	OnGone   func(home, why string)
}

// New builds the handler. key is the service key that signs hello_ok and
// purged; boxes carry its public half.
func New(st *store.Store, reg *registry.Registry, key *ecdsa.PrivateKey, log *slog.Logger) *Uplink {
	if log == nil {
		log = slog.Default()
	}
	return &Uplink{store: st, registry: reg, key: key, log: log, now: time.Now, conns: map[string]*boxConn{}}
}

var upgrader = websocket.Upgrader{
	EnableCompression: false,
	// A box sends no Origin. A browser always does, and has no business
	// here.
	CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
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
	defer conn.Close()
	conn.SetReadLimit(maxBoxFrame)
	c := &boxConn{u: u, conn: conn, ekm: ekm, tokens: rateBurst, refilled: u.now()}
	c.write = c.writeFrame
	if err := c.run(); err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
		u.log.Debug("box uplink closed", "err", err)
	}
}

// Watch asks a home's box for one-second updates for a minute. The app
// session (C3) calls it while a phone is looking.
func (u *Uplink) Watch(home string) {
	u.mu.Lock()
	c := u.conns[home]
	u.mu.Unlock()
	if c != nil {
		_ = c.send(watch{Hz: 1})
	}
}

// boxConn is one box's connection.
type boxConn struct {
	u    *Uplink
	conn *websocket.Conn
	ekm  []byte
	// write sends one frame; tests replace it.
	write   func([]byte) error
	writeMu sync.Mutex

	home   string
	pub    *ecdsa.PublicKey
	handle *store.Handle
	purged bool
	// bye is the reason the box gave for leaving, if it gave one.
	bye string

	tokens   float64
	refilled time.Time
}

func (c *boxConn) writeFrame(frame []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, frame)
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
	hello, err := c.hello(env, nonce)
	if err != nil {
		return err
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
			if current && c.u.OnGone != nil {
				c.u.OnGone(c.home, c.bye)
			}
		}()
	}

	if err := c.send(helloOK{BoxNonce: hello.BoxNonce, EKM: c.ekm, Have: map[string]string{}, RosterSeq: c.rosterSeq()}); err != nil {
		return err
	}
	if !c.purged && c.u.OnConnect != nil {
		go c.u.OnConnect(c.home)
	}

	done := make(chan struct{})
	defer close(done)
	go c.ping(done)
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
		if !c.allow() {
			return fmt.Errorf("%w: faster than %d messages a second", errProtocol, ratePerSec)
		}
		env, err := parseUplink(kind, msg)
		if err != nil {
			return err
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
	c.home, c.pub = home, pub
	return h, nil
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

func (c *boxConn) ping(done <-chan struct{}) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if c.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)) != nil {
				return
			}
		}
	}
}

// allow is a token bucket over the box's messages.
func (c *boxConn) allow() bool {
	now := c.u.now()
	c.tokens = min(rateBurst, c.tokens+now.Sub(c.refilled).Seconds()*ratePerSec)
	c.refilled = now
	if c.tokens < 1 {
		return false
	}
	c.tokens--
	return true
}

// parseUplink reads one box frame. Only binary lane 1 frames carry the
// protocol.
func parseUplink(kind int, msg []byte) (cloudwire.Envelope, error) {
	if kind != websocket.BinaryMessage {
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
	}

	if _, forwarded := cloudwire.ClassScope[env.T]; !forwarded {
		c.u.Dropped.Add(1)
		return false, nil
	}
	raw, err := env.Encode()
	if err != nil {
		return true, err
	}
	if err := c.handle.Put(env.T, raw, h.Seq, env.T == cloudwire.MsgLive && carriesTable(env.B)); err != nil {
		return true, err
	}
	if env.T == cloudwire.MsgEvent && c.u.OnEvent != nil {
		c.u.OnEvent(c.home, raw)
	}
	return false, nil
}

// carriesTable reports whether a live body holds its source table.
func carriesTable(body []byte) bool {
	var l struct {
		Sources map[string]cbor.RawMessage `cbor:"sources"`
	}
	return cloudwire.Unmarshal(body, &l) == nil && len(l.Sources) > 0
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
	if len(r.Grant.ID) != cloudwire.GrantIDBytes || r.Grant.Controller == "" || r.TTLS <= 0 ||
		!within(r.Grant.Scopes, protocol.CloudScopes) || !within(r.Grant.Purposes, protocol.CloudPurposes) {
		return fmt.Errorf("%w: a roster outside what FTW Cloud may hold", errProtocol)
	}
	for _, d := range r.Devices {
		if len(d.Key) != 32 || d.ID == "" || !within(d.Scopes, protocol.CloudScopes) {
			return fmt.Errorf("%w: a roster device the service cannot use", errProtocol)
		}
	}
	if !c.handle.SetRoster(&r) {
		return nil // older than what is held: ignored
	}
	if c.u.OnRoster != nil {
		c.u.OnRoster(c.home, &r)
	}
	raw, err := env.Encode()
	if err != nil {
		return err
	}
	return c.u.registry.SetRoster(c.home, r.RosterSeq, r.Grant.ID, raw, c.u.now())
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
	return c.send(purged{AtMs: now.UnixMilli(), What: cloudwire.PurgedHome, GrantID: grantID})
}
