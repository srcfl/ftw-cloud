package uplink

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type service struct {
	srv   *httptest.Server
	up    *Uplink
	store *store.Store
	reg   *registry.Registry
	key   *ecdsa.PrivateKey
}

func newService(t *testing.T) *service {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	st := store.New(nil)
	up := New(st, reg, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewUnstartedServer(up)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &service{srv: srv, up: up, store: st, reg: reg, key: key}
}

// box is a box's half of the uplink, enough to drive the service.
type box struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	pk   []byte
	home string
	boot []byte
	seq  uint64
	conn *websocket.Conn
}

func newBox(t *testing.T) *box {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	return &box{t: t, key: key, pk: pk, home: cloudwire.HomeID(pk), boot: bytes.Repeat([]byte{3}, 16)}
}

func (b *box) header() cloudwire.Header {
	b.seq++
	return cloudwire.Header{Seq: b.seq, Boot: b.boot, UptimeMs: int64(b.seq) * 1000}
}

// connect runs the handshake. ekmOverride replaces the box's exporter value
// in hello, as a proxy relaying the box's hello would have to.
func (b *box) connect(s *service, ekmOverride []byte) (cloudwire.HelloOK, error) {
	b.t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	conn, _, err := d.Dial("wss://"+s.srv.Listener.Addr().String()+"/v1/box", nil)
	if err != nil {
		b.t.Fatal(err)
	}
	b.conn = conn
	b.t.Cleanup(func() { _ = conn.Close() })
	cs := conn.NetConn().(*tls.Conn).ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, 32)

	env := b.read()
	var ch cloudwire.Challenge
	if env.T != cloudwire.MsgChallenge || cloudwire.Unmarshal(env.B, &ch) != nil || len(env.Sig) != 0 {
		b.t.Fatalf("first message %q", env.T)
	}
	if ekmOverride != nil {
		ekm = ekmOverride
	}
	boxNonce := bytes.Repeat([]byte{4}, 32)
	b.send(cloudwire.MsgHello, cloudwire.Hello{Header: b.header(), V: 1, PK: b.pk, Nonce: ch.Nonce,
		EKM: ekm, BoxNonce: boxNonce, Build: "test", Clock: cloudwire.ClockNTP, RosterSeq: 1,
		GrantID: bytes.Repeat([]byte{5}, 16)})

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return cloudwire.HelloOK{}, err
	}
	env, _ = parseUplink(websocket.BinaryMessage, msg)
	var ok cloudwire.HelloOK
	if env.T != cloudwire.MsgHelloOK || cloudwire.Verify(&s.key.PublicKey, b.home, env) != nil ||
		cloudwire.Unmarshal(env.B, &ok) != nil || !bytes.Equal(ok.BoxNonce, boxNonce) || !bytes.Equal(ok.EKM, ekm) {
		b.t.Fatalf("hello_ok did not check out")
	}
	return ok, nil
}

func (b *box) read() cloudwire.Envelope {
	b.t.Helper()
	_ = b.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	kind, msg, err := b.conn.ReadMessage()
	if err != nil {
		b.t.Fatalf("read: %v", err)
	}
	env, err := parseUplink(kind, msg)
	if err != nil {
		b.t.Fatal(err)
	}
	return env
}

// send seals and writes one message and returns its envelope bytes.
func (b *box) send(t string, body any) []byte {
	return b.sendAs(b.key, t, body)
}

func (b *box) sendAs(key *ecdsa.PrivateKey, t string, body any) []byte {
	env, err := cloudwire.Seal(key, b.home, t, body)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, _ := env.Encode()
	frame, _ := cloudwire.EncodeFrame(raw)
	if err := b.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		b.t.Fatal(err)
	}
	return raw
}

// closed waits for the service to hang up.
func (b *box) closed() bool {
	_ = b.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		if _, _, err := b.conn.ReadMessage(); err != nil {
			return !strings.Contains(err.Error(), "timeout")
		}
	}
}

var ownerKey = bytes.Repeat([]byte{7}, 32)

func (b *box) roster(scopes ...string) cloudwire.Roster {
	return cloudwire.Roster{Header: b.header(), RosterSeq: 1, TTLS: 86_400,
		Devices: []cloudwire.Device{{ID: "owner", Key: ownerKey, Role: "owner", Scopes: protocol.CloudScopes, Epoch: 1}},
		Grant: cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: scopes,
			Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}}
}

// wait polls until cond holds, or fails.
func wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func snapshot(t *testing.T, s *service, home string) [][]byte {
	t.Helper()
	dev, err := s.store.For(store.Principal{Kind: store.Device, Home: home, DeviceKey: ownerKey})
	if err != nil {
		return nil
	}
	snap, _ := dev.Snapshot()
	return snap.Envelopes
}

// The service holds the box's bytes, unchanged, and serves them by scope.
func TestTheServiceHoldsExactlyWhatTheBoxSent(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	live := b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1200},
		Sources: map[string]cloudwire.Source{"x": {Kind: "driver", State: "live", StaleAfterMs: 10_000}}, SrcRev: 1})
	plan := b.send(cloudwire.MsgPlan, map[string]any{"seq": b.header().Seq, "decisionId": "d1"})
	hb := b.send(cloudwire.MsgHB, cloudwire.HB{Header: b.header(), Clock: cloudwire.ClockNTP, SrcRev: 1, LiveSeq: 3})

	wait(t, "the hb", func() bool { return len(snapshot(t, s, b.home)) == 2 })
	got := snapshot(t, s, b.home)
	if !bytes.Equal(got[0], live) || !bytes.Equal(got[1], hb) {
		t.Fatal("the service changed the box's bytes")
	}
	for _, e := range got {
		if bytes.Equal(e, plan) {
			t.Fatal("plan was served without ftw.plan.read in the grant")
		}
	}
	if h, ok, _ := s.reg.Get(b.home); !ok || h.RosterSeq != 1 || !bytes.Equal(h.PK, b.pk) {
		t.Fatalf("registry %+v", h)
	}
}

// A hello that carries another TLS session's exporter value is a hello
// relayed through a proxy. The service closes, and no home exists.
func TestAHelloFromAnotherSessionIsRefused(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	if _, err := b.connect(s, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("the service answered a hello bound to another session")
	}
	if _, ok, _ := s.reg.Get(b.home); ok {
		t.Fatal("a refused hello claimed a home")
	}
}

func TestAMessageNotSignedByTheBoxCloses(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.sendAs(other, cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 9999}})
	if !b.closed() {
		t.Fatal("the service kept a connection that sent a forged message")
	}
	if got := snapshot(t, s, b.home); len(got) != 0 {
		t.Fatal("a forged live was stored")
	}
}

func TestARosterBeyondFTWCloudIsRefused(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeDispatchWrite))
	if !b.closed() {
		t.Fatal("a roster granting a write scope was kept")
	}
}

// bye with purge deletes the home and returns a receipt signed with the
// service key, which a box whose first receipt was lost can ask for again.
func TestPurgeDeletesTheHomeAndSignsAReceipt(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	r := b.roster(protocol.ScopeLiveRead)
	b.send(cloudwire.MsgRoster, r)
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1}})
	wait(t, "the live", func() bool { return len(snapshot(t, s, b.home)) == 1 })

	b.send(cloudwire.MsgBye, cloudwire.Bye{Header: b.header(), Why: cloudwire.ByeRevoked, Purge: true})
	receipt := func() {
		env := b.read()
		var p cloudwire.Purged
		if env.T != cloudwire.MsgPurged || cloudwire.Verify(&s.key.PublicKey, b.home, env) != nil ||
			cloudwire.Unmarshal(env.B, &p) != nil || p.What != cloudwire.PurgedHome || !bytes.Equal(p.GrantID, r.Grant.ID) {
			t.Fatalf("receipt %q does not check out", env.T)
		}
	}
	receipt()
	if _, ok, _ := s.reg.Get(b.home); ok {
		t.Fatal("the registry kept the home")
	}
	if _, err := s.store.For(store.Principal{Kind: store.Device, Home: b.home, DeviceKey: ownerKey}); err == nil {
		t.Fatal("memory kept the home")
	}

	_ = b.conn.Close()
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgBye, cloudwire.Bye{Header: b.header(), Why: cloudwire.ByeRevoked, Purge: true})
	receipt()

	// A purged home's box may say only bye.
	_ = b.conn.Close()
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header()})
	if !b.closed() {
		t.Fatal("a purged home's box sent readings and stayed")
	}
}

func TestAnUnknownBoxMessageIsCountedNotFatal(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	_, _ = b.connect(s, nil)
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	b.send("stats.future", map[string]any{"seq": b.header().Seq})
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1}})
	wait(t, "the live after the stranger", func() bool { return len(snapshot(t, s, b.home)) == 1 })
	if s.up.Dropped.Load() != 1 {
		t.Fatalf("dropped %d", s.up.Dropped.Load())
	}
}

func TestASecondUplinkReplacesTheFirst(t *testing.T) {
	s := newService(t)
	first := newBox(t)
	_, _ = first.connect(s, nil)
	second := *first
	second.conn = nil
	if _, err := second.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	if !first.closed() {
		t.Fatal("two uplinks for one home")
	}
}

// The service can say five things to a box, and they are the protocol's five.
func TestDownlinkIsTheProtocolsClosedSet(t *testing.T) {
	s := newService(t)
	all := []down{challenge{V: 1, Nonce: make([]byte, 32)}, helloOK{Have: map[string]string{}},
		watch{Hz: 1}, resync{What: []string{cloudwire.ResyncFull}}, purged{What: cloudwire.PurgedHome},
		tun{Dev: "q5Lw0Zb1", Sid: 1, D: []byte{1}}}
	var names []string
	for _, m := range all {
		frame, err := s.up.encodeDown("home", m)
		if err != nil {
			t.Fatal(err)
		}
		if len(frame) > cloudwire.MaxServiceFrame {
			t.Fatalf("%d bytes", len(frame))
		}
		env, err := parseUplink(websocket.BinaryMessage, frame)
		if err != nil {
			t.Fatal(err)
		}
		_, _, signed := m.down()
		if signed != (cloudwire.Verify(&s.key.PublicKey, "home", env) == nil) {
			t.Fatalf("%s: signed=%v", env.T, signed)
		}
		names = append(names, env.T)
	}
	if !slices.Equal(names, cloudwire.Downlink) {
		t.Fatalf("downlink %v, protocol %v", names, cloudwire.Downlink)
	}
}

// Whatever a box with a valid key signs, the service stores it, ignores it
// or closes, and never panics.
func FuzzBoxMessage(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	home := cloudwire.HomeID(pk)
	for _, t := range []string{cloudwire.MsgLive, cloudwire.MsgRoster, cloudwire.MsgBye, cloudwire.MsgHB, "x"} {
		body, _ := cloudwire.Marshal(map[string]any{"seq": 1, "boot": []byte{1}, "purge": true, "rosterSeq": 1})
		f.Add(t, body)
	}
	f.Fuzz(func(t *testing.T, typ string, body []byte) {
		reg, err := registry.Open(filepath.Join(t.TempDir(), "r.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer reg.Close()
		st := store.New(nil)
		u := New(st, reg, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
		handle, _ := st.For(store.Principal{Kind: store.Box, Home: home})
		_ = reg.Claim(home, pk, time.Now())
		c := &boxConn{u: u, home: home, pub: &key.PublicKey, handle: handle, write: func([]byte) error { return nil }}
		env, err := cloudwire.SealBytes(key, home, typ, body)
		if err != nil || typ == "" {
			return
		}
		_, _ = c.apply(env)
	})
}

// Whatever tun body a box sends, the service routes it, ends it or closes,
// and never panics.
func FuzzBoxTun(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	home := cloudwire.HomeID(pk)
	for _, seed := range []any{
		cloudwire.Tun{Dev: "owner", Sid: 1, D: []byte{1}},
		cloudwire.Tun{Dev: "owner", Sid: 1},
		map[string]any{"dev": 7, "sid": "x", "d": "y"},
	} {
		body, _ := cloudwire.Marshal(seed)
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		st := store.New(nil)
		u := New(st, nil, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
		handle, _ := st.For(store.Principal{Kind: store.Box, Home: home})
		now := time.Now()
		c := &boxConn{u: u, home: home, pub: &key.PublicKey, handle: handle, tun: true,
			write:  func([]byte) error { return nil },
			upMsgs: newBucket(tunMsgBurst, tunMsgPerSec, now), upBytes: newBucket(tunByteBurst, tunBytePerSec, now),
			upHardMsgs: newBucket(2*tunMsgBurst, 2*tunMsgPerSec, now), upHardBytes: newBucket(2*tunByteBurst, 2*tunBytePerSec, now)}
		_ = c.fromBox(cloudwire.Envelope{T: cloudwire.MsgTun, B: body})
	})
}
