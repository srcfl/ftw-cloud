package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	handshakeTimeout = 10 * time.Second
	// readTimeout: the service pings every 15 s.
	readTimeout  = 60 * time.Second
	writeTimeout = 10 * time.Second
	// rosterSeq is the one roster each box signs; a box sends it again only
	// when hello_ok says the service holds an older one.
	rosterSeq = 1
)

// box is one home's gateway: one uplink, a signed roster that lists its
// phones, a live every -live, and every tun echoed straight back.
type box struct {
	h      *harness
	key    *ecdsa.PrivateKey
	pk     []byte
	home   string
	boot   []byte
	born   time.Time
	grant  cloudwire.Grant
	phones []appwire.KeyPair
	// ready is closed once the service has the roster, so phones dial a
	// home that lists them.
	ready     chan struct{}
	readyOnce sync.Once

	// wmu orders writes and the header's seq with them.
	wmu     sync.Mutex
	seq     uint64
	conn    atomic.Pointer[websocket.Conn]
	stormed atomic.Bool

	// sent is when each recent live left, by seq, for the phones' latency.
	liveMu sync.Mutex
	sent   [64]liveSent
}

type liveSent struct {
	seq     uint64
	at      time.Time
	counted bool
}

func newBox(h *harness) *box {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	b := &box{h: h, key: key, pk: pk, home: cloudwire.HomeID(pk), boot: randBytes(cloudwire.BootBytes),
		born: time.Now(), ready: make(chan struct{}),
		grant: cloudwire.Grant{Scopes: []string{}, Purposes: []string{}, Controller: cloudwire.ControllerSourceful}}
	if h.cfg.copy {
		b.grant = cloudwire.Grant{ID: randBytes(cloudwire.GrantIDBytes), Scopes: []string{protocol.ScopeLiveRead},
			Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}
	}
	for range h.cfg.phones {
		k, _ := appwire.GenerateKeyPair()
		b.phones = append(b.phones, k)
	}
	return b
}

func (b *box) run(ctx context.Context, start time.Duration) {
	if !sleep(ctx, start) {
		return
	}
	attempt := 0
	for ctx.Err() == nil && !b.h.stopping.Load() {
		began := time.Now()
		conn, err := b.connect(ctx)
		if err != nil {
			if !b.h.redial(ctx, "box."+stepOf(err), err, &attempt) {
				return
			}
			continue
		}
		hs := time.Since(began)
		b.h.stats.boxHS.add(hs)
		// Stored before the storm flag is read, so a storm that comes
		// meanwhile either closes this socket or counts it as back.
		b.conn.Store(conn)
		if b.stormed.CompareAndSwap(true, false) {
			b.h.recovered(hs)
		}
		attempt = 0
		err = b.session(ctx, conn)
		if b.stormed.Load() && ctx.Err() == nil {
			if !sleep(ctx, jitter(b.h.cfg.stormJitter)) {
				return
			}
			continue
		}
		if !b.h.redial(ctx, "box.session", err, &attempt) {
			return
		}
	}
}

// connect dials /v1/box and runs the handshake: challenge, a hello signed
// over the nonce and the TLS exporter, hello_ok checked against the service
// key. Then the roster, if the service lacks it.
func (b *box) connect(ctx context.Context) (*websocket.Conn, error) {
	conn, _, err := b.h.dialer.DialContext(ctx, b.h.url+"/v1/box", nil)
	if err != nil {
		return nil, &failure{"dial", err}
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	tc, _ := conn.NetConn().(*tls.Conn)
	if tc == nil {
		return nil, &failure{"handshake", errors.New("not TLS")}
	}
	cs := tc.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
	if err != nil {
		return nil, &failure{"handshake", err}
	}
	env, err := readEnvelope(conn)
	var ch cloudwire.Challenge
	if err != nil || env.T != cloudwire.MsgChallenge || cloudwire.Unmarshal(env.B, &ch) != nil {
		return nil, &failure{"handshake", orErr(err, "first message %q", env.T)}
	}
	boxNonce := randBytes(cloudwire.NonceBytes)
	b.wmu.Lock()
	err = b.sealLocked(conn, cloudwire.MsgHello, cloudwire.Hello{Header: b.headerLocked(), V: cloudwire.Version, PK: b.pk,
		Nonce: ch.Nonce, EKM: ekm, BoxNonce: boxNonce, Build: "ftwload", Clock: cloudwire.ClockNTP,
		Caps:      []string{cloudwire.MsgLive, cloudwire.MsgRoster, cloudwire.CapTun, cloudwire.CapShard},
		RosterSeq: rosterSeq, GrantID: b.grant.ID})
	b.wmu.Unlock()
	if err != nil {
		return nil, &failure{"handshake", err}
	}
	env, err = readEnvelope(conn)
	var hok cloudwire.HelloOK
	switch {
	case err != nil:
		return nil, &failure{"handshake", err}
	case env.T != cloudwire.MsgHelloOK || cloudwire.Verify(b.h.service, b.home, env) != nil ||
		cloudwire.Unmarshal(env.B, &hok) != nil || !bytes.Equal(hok.BoxNonce, boxNonce) || !bytes.Equal(hok.EKM, ekm):
		return nil, &failure{"handshake", fmt.Errorf("hello_ok did not check out (%q)", env.T)}
	}
	if hok.RosterSeq < rosterSeq {
		if err := b.sendRoster(conn); err != nil {
			return nil, &failure{"handshake", err}
		}
	}
	b.readyOnce.Do(func() { close(b.ready) })
	keepAlive(conn)
	ok = true
	return conn, nil
}

func (b *box) sendRoster(conn *websocket.Conn) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	r := cloudwire.Roster{Header: b.headerLocked(), RosterSeq: rosterSeq, TTLS: 86_400, Grant: b.grant}
	for _, k := range b.phones {
		r.Devices = append(r.Devices, cloudwire.Device{ID: cloudwire.DeviceID(k.Public()), Key: k.Public(), Role: "owner",
			Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1, Tun: true})
	}
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].ID < r.Devices[j].ID })
	return b.sealLocked(conn, cloudwire.MsgRoster, r)
}

// session sends live and echoes tun until the socket ends.
func (b *box) session(ctx context.Context, conn *websocket.Conn) error {
	b.h.up(&b.h.boxesUp, b.h.wantBoxes, &b.h.allBoxesAt)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	done := make(chan struct{})
	go b.liveLoop(conn, done)
	err := b.readLoop(conn)
	close(done)
	stop()
	_ = conn.Close()
	b.conn.CompareAndSwap(conn, nil)
	b.h.boxesUp.Add(-1)
	return err
}

func (b *box) liveLoop(conn *websocket.Conn, done <-chan struct{}) {
	t := time.NewTimer(jitter(b.h.cfg.live))
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		t.Reset(b.h.cfg.live)
		b.wmu.Lock()
		hdr := b.headerLocked()
		env, err := cloudwire.Seal(b.key, b.home, cloudwire.MsgLive, cloudwire.Live{Header: hdr,
			Fields: map[string]int64{"1": 1200, "2": -800, "3": 400}, Ages: map[string]int64{}})
		if err == nil {
			b.liveMu.Lock()
			b.sent[hdr.Seq%64] = liveSent{seq: hdr.Seq, at: time.Now(), counted: b.h.measuring.Load()}
			b.liveMu.Unlock()
			err = b.writeLocked(conn, env)
		}
		b.wmu.Unlock()
		if err != nil {
			return
		}
	}
}

// readLoop echoes each tun with the same dev, sid and d, as if the box
// answered a command. Everything else is ignored.
func (b *box) readLoop(conn *websocket.Conn) error {
	for {
		env, err := readEnvelope(conn)
		if err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		if env.T != cloudwire.MsgTun {
			continue
		}
		var t cloudwire.Tun
		if cloudwire.Unmarshal(env.B, &t) != nil || t.Ended() {
			continue
		}
		b.wmu.Lock()
		err = b.writeLocked(conn, cloudwire.Envelope{T: cloudwire.MsgTun, B: env.B})
		b.wmu.Unlock()
		if err != nil {
			return err
		}
	}
}

// headerLocked is the next header: seq rises per message, per boot, across
// reconnects. The caller holds wmu.
func (b *box) headerLocked() cloudwire.Header {
	b.seq++
	wall := time.Now().UnixMilli()
	return cloudwire.Header{Seq: b.seq, Boot: b.boot, UptimeMs: time.Since(b.born).Milliseconds(), WallMs: &wall}
}

func (b *box) sealLocked(conn *websocket.Conn, t string, body any) error {
	env, err := cloudwire.Seal(b.key, b.home, t, body)
	if err != nil {
		return err
	}
	return b.writeLocked(conn, env)
}

func (b *box) writeLocked(conn *websocket.Conn, env cloudwire.Envelope) error {
	raw, err := env.Encode()
	if err != nil {
		return err
	}
	frame, err := cloudwire.EncodeFrame(raw)
	if err != nil {
		return err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return conn.WriteMessage(websocket.BinaryMessage, frame)
}

func readEnvelope(conn *websocket.Conn) (cloudwire.Envelope, error) {
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return cloudwire.Envelope{}, err
	}
	payload, err := cloudwire.DecodeFrame(msg)
	if err != nil {
		return cloudwire.Envelope{}, err
	}
	return cloudwire.DecodeEnvelope(payload)
}

// keepAlive answers the service's pings and keeps the read deadline ahead.
func keepAlive(conn *websocket.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	conn.SetPingHandler(func(data string) error {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
		_ = conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(writeTimeout))
		return nil
	})
}

// failure names the step a dial failed at: dial or handshake.
type failure struct {
	step string
	err  error
}

func (f *failure) Error() string { return f.step + ": " + f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

func stepOf(err error) string {
	var f *failure
	if errors.As(err, &f) {
		return f.step
	}
	return "dial"
}

func orErr(err error, format string, args ...any) error {
	if err != nil {
		return err
	}
	return fmt.Errorf(format, args...)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randN(n int64) int64 { return mrand.Int64N(n) }
