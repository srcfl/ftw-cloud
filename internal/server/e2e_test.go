package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/appsession"
	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/quicdoor"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/token"
	"github.com/srcfl/ftw-cloud/internal/uplink"
	"github.com/srcfl/ftw-cloud/internal/wire"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The whole service, wired as ftwcloudd wires it, behind TLS 1.3, with a
// box on its uplink and a watch that reads it the way watchOS allows: one
// HTTPS POST at a time.

type capturedApple struct {
	mu   sync.Mutex
	sent []apns.Notification
}

func (a *capturedApple) Send(_ context.Context, n apns.Notification) (apns.Result, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sent = append(a.sent, n)
	return apns.Result{Status: http.StatusOK}, nil
}

func (a *capturedApple) taken() []apns.Notification {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.sent
	a.sent = nil
	return out
}

type stack struct {
	t          *testing.T
	srv        *httptest.Server
	st         *store.Store
	serviceKey *ecdsa.PrivateKey
	noise      appwire.KeyPair
	apple      *capturedApple
	up         *uplink.Uplink
	reg        *registry.Registry
	app        *appsession.Server
	// quicAddr is the stack's QUIC door, once s.quic has started it.
	quicAddr string
	door     *quicdoor.Door
}

func newStack(t *testing.T) *stack {
	t.Helper()
	serviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	noise, _ := appwire.GenerateKeyPair()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.New(nil)
	st.UseSuspensions(reg.Suspended)
	up := uplink.New(st, reg, serviceKey, log)
	apple := &capturedApple{}
	pushSvc := push.New(reg, apple, log)
	pushSvc.WatchApp = "energy.ftw.app.watchkitapp"
	tokens := token.New(st, reg, log)
	app := appsession.New(st, reg, up, noise, log)
	app.Push, app.Tokens, app.Tunnel, app.Exchange = pushSvc, tokens, up, up
	up.OnHeld = pushSvc.Held
	up.OnRoster = func(home string, r *cloudwire.Roster) {
		pushSvc.Roster(home, r)
		tokens.Roster(home, r)
	}
	up.OnGone = pushSvc.BoxGone
	up.OnConnect = func(home string, conn uint64) {
		app.BoxConnected(home)
		pushSvc.BoxConnected(home, conn)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go pushSvc.Run(ctx)

	s := &Server{Store: st, Registry: reg, Uplink: up, App: app, Tokens: tokens, Log: log}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &stack{t: t, srv: srv, st: st, serviceKey: serviceKey, noise: noise, apple: apple, up: up, reg: reg, app: app}
}

// testBox is a box's half of the uplink.
type testBox struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	home string
	boot []byte
	seq  uint64
	// liveSeq is the seq of the newest live sent, which hb names.
	liveSeq uint64
	conn    wire.Conn
	// heard is what the service told the box after hello_ok. An x it
	// answers at once, with "answer to " before the watch's d.
	heard chan string
	start time.Time
	mu    sync.Mutex
}

func (s *stack) connectBox(caps ...string) *testBox {
	s.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	b := &testBox{t: s.t, key: key, home: cloudwire.HomeID(pk), boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes),
		heard: make(chan string, 16), start: time.Now()}
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	conn, _, err := d.Dial(strings.Replace(s.srv.URL, "https://", "wss://", 1)+"/v1/box", nil)
	if err != nil {
		s.t.Fatal(err)
	}
	s.t.Cleanup(func() { _ = conn.Close() })
	b.conn = conn
	cs := conn.NetConn().(*tls.Conn).ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
	env := b.read()
	var ch cloudwire.Challenge
	if env.T != cloudwire.MsgChallenge || cloudwire.Unmarshal(env.B, &ch) != nil {
		s.t.Fatalf("first message %q", env.T)
	}
	boxNonce := bytes.Repeat([]byte{4}, cloudwire.NonceBytes)
	b.send(cloudwire.MsgHello, cloudwire.Hello{Header: b.header(), V: cloudwire.Version, PK: pk, Nonce: ch.Nonce, EKM: ekm,
		BoxNonce: boxNonce, Build: "e2e", Clock: cloudwire.ClockNTP, RosterSeq: 1, GrantID: bytes.Repeat([]byte{5}, 16), Caps: caps})
	env = b.read()
	if env.T != cloudwire.MsgHelloOK || cloudwire.Verify(&s.serviceKey.PublicKey, b.home, env) != nil {
		s.t.Fatal("hello_ok did not check out")
	}
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				close(b.heard)
				return
			}
			payload, _ := cloudwire.DecodeFrame(msg)
			e, _ := cloudwire.DecodeEnvelope(payload)
			var x cloudwire.X
			if e.T == cloudwire.MsgX && cloudwire.Unmarshal(e.B, &x) == nil {
				x.D = append([]byte("answer to "), x.D...)
				body, _ := cloudwire.Marshal(x)
				raw, _ := cloudwire.Envelope{T: cloudwire.MsgX, B: body}.Encode()
				frame, _ := cloudwire.EncodeFrame(raw)
				b.mu.Lock()
				_ = conn.WriteMessage(websocket.BinaryMessage, frame)
				b.mu.Unlock()
			}
			b.heard <- e.T
		}
	}()
	return b
}

func (b *testBox) read() cloudwire.Envelope {
	b.t.Helper()
	_ = b.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := b.conn.ReadMessage()
	if err != nil {
		b.t.Fatal(err)
	}
	payload, err := cloudwire.DecodeFrame(msg)
	if err != nil {
		b.t.Fatal(err)
	}
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil {
		b.t.Fatal(err)
	}
	return env
}

func (b *testBox) header() cloudwire.Header {
	b.seq++
	wall := time.Now().UnixMilli()
	return cloudwire.Header{Seq: b.seq, Boot: b.boot, UptimeMs: time.Since(b.start).Milliseconds(), WallMs: &wall}
}

func (b *testBox) send(t string, body any) []byte {
	b.t.Helper()
	env, err := cloudwire.Seal(b.key, b.home, t, body)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, _ := env.Encode()
	frame, _ := cloudwire.EncodeFrame(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		b.t.Fatal(err)
	}
	return raw
}

func (b *testBox) roster(seq uint64, devices ...cloudwire.Device) {
	b.send(cloudwire.MsgRoster, cloudwire.Roster{Header: b.header(), RosterSeq: seq, TTLS: 86_400, Devices: devices,
		Grant: cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: protocol.CloudScopes,
			Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}})
}

func (b *testBox) live(full bool) []byte {
	l := cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1800}, SrcRev: 1, Ages: map[string]int64{"m": 300}}
	b.liveSeq = l.Seq
	if full {
		l.Sources = map[string]cloudwire.Source{"m": {Kind: "driver", State: protocol.SourceLive, StaleAfterMs: 10_000}}
		l.FieldSources = map[string][]string{"2": {"m"}}
	}
	return b.send(cloudwire.MsgLive, l)
}

func (b *testBox) hb() []byte {
	return b.send(cloudwire.MsgHB, cloudwire.HB{Header: b.header(), Clock: cloudwire.ClockNTP, SrcRev: 1,
		LiveSeq: b.liveSeq, Ages: map[string]int64{"m": 300}})
}

// heardWatch reports whether the service asked the box for one-second
// updates within a second.
func (b *testBox) heardWatch() bool {
	deadline := time.After(time.Second)
	for {
		select {
		case t, ok := <-b.heard:
			if !ok {
				return false
			}
			if t == cloudwire.MsgWatch {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// watchClient is the watch's side of the one-shot read: Noise IK message 1
// in one POST, message 2 and what follows in the answer. It is the
// reference the watch's Swift port follows.
type watchClient struct {
	t       *testing.T
	http    *http.Client
	base    string
	key     appwire.KeyPair
	service []byte
	home    string
}

// call posts one message 1 and returns the status, message 2's payload and
// the envelopes that followed it.
func (w *watchClient) call(t string, body any) (int, []byte, [][]byte) {
	w.t.Helper()
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: w.key, RemoteStatic: w.service,
		Prologue: cloudwire.OncePrologue(w.home)})
	if err != nil {
		w.t.Fatal(err)
	}
	payload, _ := cloudwire.Unsigned(t, body)
	msg1, err := init.WriteMessage(payload)
	if err != nil {
		w.t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, w.base+cloudwire.OncePath+"?"+cloudwire.AppHomeParam+"="+w.home, bytes.NewReader(msg1))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := w.http.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}
	parts, err := cloudwire.SplitOnceAnswer(answer)
	if err != nil {
		w.t.Fatal(err)
	}
	reply, err := init.ReadMessage(parts[0])
	if err != nil {
		w.t.Fatal(err)
	}
	keys, _ := init.Split()
	tr := appwire.NewTransport(keys)
	var following [][]byte
	for _, m := range parts[1:] {
		frame, err := tr.Decrypt(m)
		if err != nil {
			w.t.Fatal(err)
		}
		env, err := cloudwire.DecodeFrame(frame)
		if err != nil {
			w.t.Fatal(err)
		}
		following = append(following, env)
	}
	return resp.StatusCode, reply, following
}

// read asks for the snapshot less what the watch holds, and feeds every
// envelope through the freshness rules with the box key the watch learned
// from the box, never from the service.
func (w *watchClient) read(view *cloudwire.View, have cloudwire.Have, hz int) (int, cloudwire.Snapshot, [][]byte) {
	w.t.Helper()
	status, reply, following := w.call(cloudwire.MsgRead, cloudwire.Read{Have: have, Hz: hz})
	if status != http.StatusOK {
		return status, cloudwire.Snapshot{}, nil
	}
	snap, err := cloudwire.ParseSnapshot(reply)
	if err != nil || snap.More != len(following) {
		w.t.Fatalf("snapshot %+v, %d followed: %v", snap, len(following), err)
	}
	var all [][]byte
	for _, e := range snap.Envelopes {
		all = append(all, e)
	}
	all = append(all, following...)
	arrival := time.Now().UnixMilli()
	for _, raw := range all {
		env, err := cloudwire.DecodeEnvelope(raw)
		if err != nil {
			w.t.Fatal(err)
		}
		if err := view.Accept(env, arrival); err != nil {
			w.t.Fatalf("the watch dropped a %s: %v", env.T, err)
		}
	}
	return status, snap, all
}

// A box with FTW Cloud on, a watch in its roster, and the watch reading,
// asking for its token, registering for alerts and being removed, all over
// real TLS with the service wired as ftwcloudd wires it.
func TestAWatchReadsItsHomeEndToEnd(t *testing.T) {
	s := newStack(t)
	box := s.connectBox()
	phoneKey, _ := appwire.GenerateKeyPair()
	watchKey, _ := appwire.GenerateKeyPair()
	phone := cloudwire.Device{ID: "phone", Key: phoneKey.Public(), Role: "owner", Scopes: protocol.CloudScopes, Epoch: 1}
	watchDev := cloudwire.Device{ID: "watch", Key: watchKey.Public(), Role: "watch",
		Scopes: []string{protocol.ScopeLiveRead, protocol.ScopePlanRead, protocol.ScopeEventsRead}, Epoch: 1}
	box.roster(1, phone, watchDev)
	full := box.live(true)
	prices := box.send(cloudwire.MsgPrices, cloudwire.Prices{Header: box.header(), Zone: "SE3", Currency: "SEK",
		SpotMinor: []*int64{}, TotalMinor: []*int64{}})
	lp := box.send(cloudwire.MsgLP, cloudwire.LP{Header: box.header(), Loadpoints: []cloudwire.Loadpoint{}, Feedback: []cloudwire.Feedback{}})
	hb := box.hb()
	waitHeld(t, s.st, box.home, phoneKey, 4)

	boxPub := &box.key.PublicKey
	watch := &watchClient{t: t, http: s.srv.Client(), base: s.srv.URL, key: watchKey, service: s.noise.Public(), home: box.home}
	view := cloudwire.NewView(box.home, boxPub)

	// The first read: everything the watch may read, the box's bytes, live.
	status, snap, all := watch.read(view, cloudwire.Have{}, cloudwire.HzLooking)
	if status != http.StatusOK || !snap.Online || len(all) != 4 {
		t.Fatalf("first read: %d, online %v, %d envelopes", status, snap.Online, len(all))
	}
	for i, want := range [][]byte{full, prices, lp, hb} {
		if !bytes.Equal(all[i], want) {
			t.Fatalf("envelope %d is not the box's bytes", i)
		}
	}
	g := view.Grade(time.Now().UnixMilli())
	if !g.Anchored || g.Sources["m"] != protocol.SourceLive || g.Fields["2"] != protocol.SourceLive {
		t.Fatalf("the first read grades %+v", g)
	}
	if !box.heardWatch() {
		t.Fatal("hz 1 did not ask the box for one-second updates")
	}

	// The second read carries only what is new.
	delta := box.live(false)
	waitHeld(t, s.st, box.home, phoneKey, 5)
	if _, _, all = watch.read(view, haveOf(t, all), cloudwire.HzAway); len(all) != 1 || !bytes.Equal(all[0], delta) {
		t.Fatalf("the second read carried %d envelopes", len(all))
	}

	// The watch's own token reads live, prices and hb.
	status, reply, _ := watch.call(cloudwire.MsgTokenGet, struct{}{})
	env, _ := cloudwire.DecodeEnvelope(reply)
	var tok cloudwire.Token
	if status != http.StatusOK || env.T != cloudwire.MsgToken || cloudwire.Unmarshal(env.B, &tok) != nil {
		t.Fatalf("token.get: %d %q", status, env.T)
	}
	code, now := s.now(tok.Token)
	if code != http.StatusOK || len(now.Envelopes) != 4 {
		t.Fatalf("the watch's token read %d, %d envelopes", code, len(now.Envelopes))
	}
	for _, e := range now.Envelopes {
		if bytes.Equal(e, lp) {
			t.Fatal("a token read lp")
		}
	}

	// The watch and its phone register for alerts; an event reaches both
	// with the same payload, the watch on its own topic.
	phoneClient := *watch
	phoneClient.key = phoneKey
	for _, c := range []struct {
		w   *watchClient
		app string
	}{{watch, cloudwire.PushAppWatch}, {&phoneClient, cloudwire.PushAppIPhone}} {
		if status, _, _ := c.w.call(cloudwire.MsgPushRegister, cloudwire.PushRegister{APNsToken: []byte(c.app),
			Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert, App: c.app}); status != http.StatusOK {
			t.Fatalf("%s push.register: %d", c.app, status)
		}
	}
	box.send(cloudwire.MsgEvent, cloudwire.Event{Header: box.header(), EventID: "e1", Kind: protocol.PushChargingInterrupted,
		Severity: cloudwire.SeverityWarning, Args: map[string]string{}})
	var alerts []apns.Notification
	waitFor(t, "two alerts", func() bool { alerts = append(alerts, s.apple.taken()...); return len(alerts) == 2 })
	if !bytes.Equal(alerts[0].Payload, alerts[1].Payload) {
		t.Fatal("the watch and its phone got different alerts")
	}
	topics := map[string]string{string(alerts[0].DeviceToken): alerts[0].App, string(alerts[1].DeviceToken): alerts[1].App}
	if topics[cloudwire.PushAppWatch] != "energy.ftw.app.watchkitapp" || topics[cloudwire.PushAppIPhone] != "" {
		t.Fatalf("alert topics %v", topics)
	}

	// The box removes the watch: within a second its reads, its token and
	// its alerts are gone, and the phone reads on.
	removed := time.Now()
	box.roster(2, phone)
	waitFor(t, "the watch refused", func() bool {
		status, _, _ := watch.call(cloudwire.MsgRead, cloudwire.Read{})
		return status == http.StatusForbidden
	})
	if took := time.Since(removed); took > time.Second {
		t.Fatalf("the watch was refused %v after the roster", took)
	}
	if code, _ := s.now(tok.Token); code != http.StatusUnauthorized {
		t.Fatalf("the removed watch's token read %d", code)
	}
	box.send(cloudwire.MsgEvent, cloudwire.Event{Header: box.header(), EventID: "e2", Kind: protocol.PushChargingInterrupted,
		Severity: cloudwire.SeverityWarning, Args: map[string]string{}})
	alerts = nil
	waitFor(t, "the phone's alert", func() bool { alerts = append(alerts, s.apple.taken()...); return len(alerts) >= 1 })
	if len(alerts) != 1 || string(alerts[0].DeviceToken) != cloudwire.PushAppIPhone {
		t.Fatalf("after removal, alerts went to %d devices", len(alerts))
	}
}

// The service cannot make data look fresher than the box made it: when the
// box goes quiet, a read says so, and the watch's freshness rules age what
// it holds until it is down.
func TestAOnceReadNeverLooksFresherThanTheBox(t *testing.T) {
	s := newStack(t)
	box := s.connectBox()
	watchKey, _ := appwire.GenerateKeyPair()
	box.roster(1, cloudwire.Device{ID: "watch", Key: watchKey.Public(), Role: "watch",
		Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1})
	box.live(true)
	box.hb()
	waitHeld(t, s.st, box.home, watchKey, 2)
	_ = box.conn.Close()
	waitFor(t, "the box to go", func() bool {
		x, err := s.st.For(store.Principal{Kind: store.Device, Home: box.home, DeviceKey: watchKey.Public()})
		if err != nil {
			return false
		}
		snap, _ := x.Snapshot()
		return !snap.Online
	})

	watch := &watchClient{t: t, http: s.srv.Client(), base: s.srv.URL, key: watchKey, service: s.noise.Public(), home: box.home}
	view := cloudwire.NewView(box.home, &box.key.PublicKey)
	status, snap, all := watch.read(view, cloudwire.Have{}, cloudwire.HzLooking)
	if status != http.StatusOK || snap.Online || len(all) != 2 {
		t.Fatalf("after the box went: %d, online %v, %d envelopes", status, snap.Online, len(all))
	}
	nowMs := time.Now().UnixMilli()
	if g := view.Grade(nowMs); g.Sources["m"] != protocol.SourceLive {
		t.Fatalf("just after: %s", g.Sources["m"])
	}
	if g := view.Grade(nowMs + 70_000); g.Sources["m"] != protocol.SourceDown || g.Fields["2"] == protocol.SourceLive {
		t.Fatalf("70 s later the source is %s and the field %s", g.Sources["m"], g.Fields["2"])
	}
}

// haveOf is what a watch holds after accepting envelopes: their boot and
// the highest seq per class.
func haveOf(t *testing.T, envelopes [][]byte) cloudwire.Have {
	t.Helper()
	have := cloudwire.Have{Seq: map[string]uint64{}}
	for _, raw := range envelopes {
		env, _ := cloudwire.DecodeEnvelope(raw)
		var hdr cloudwire.Header
		if err := cloudwire.Unmarshal(env.B, &hdr); err != nil {
			t.Fatal(err)
		}
		have.Boot = hdr.Boot
		have.Seq[env.T] = max(have.Seq[env.T], hdr.Seq)
	}
	return have
}

func (s *stack) now(tok string) (int, token.Now) {
	s.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, s.srv.URL+"/v1/now", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := s.srv.Client().Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var n token.Now
	if resp.StatusCode == http.StatusOK {
		if err := cloudwire.Unmarshal(body, &n); err != nil {
			s.t.Fatal(err)
		}
	}
	return resp.StatusCode, n
}

// A watch whose roster entry has tun sends its exchange through the real
// uplink to its box and back; with nothing the copy lets it read, it reads
// nothing. When the box goes, the answer is empty and comes at once.
func TestAWatchExchangesWithItsBoxEndToEnd(t *testing.T) {
	s := newStack(t)
	box := s.connectBox(cloudwire.CapX)
	watchKey, _ := appwire.GenerateKeyPair()
	box.roster(1, cloudwire.Device{ID: "watch", Key: watchKey.Public(), Role: "watch", Tun: true, Epoch: 1})
	waitFor(t, "the roster", func() bool {
		_, err := s.st.For(store.Principal{Kind: store.Device, Home: box.home, DeviceKey: watchKey.Public()})
		return err == nil
	})
	watch := &watchClient{t: t, http: s.srv.Client(), base: s.srv.URL, key: watchKey, service: s.noise.Public(), home: box.home}
	answer := func() (int, []byte) {
		status, reply, _ := watch.call(cloudwire.MsgX, cloudwire.AppX{D: []byte("message 1")})
		var x cloudwire.AppX
		if env, err := cloudwire.DecodeEnvelope(reply); status == http.StatusOK && (err != nil || cloudwire.Unmarshal(env.B, &x) != nil) {
			t.Fatalf("message 2: %v", err)
		}
		return status, x.D
	}
	if status, d := answer(); status != http.StatusOK || string(d) != "answer to message 1" {
		t.Fatalf("%d %q", status, d)
	}
	if status, _, _ := watch.call(cloudwire.MsgRead, cloudwire.Read{}); status != http.StatusForbidden {
		t.Fatalf("a read with no scope: %d", status)
	}
	_ = box.conn.Close()
	waitFor(t, "the box to go", func() bool { return s.up.Boxes() == 0 })
	start := time.Now()
	if status, d := answer(); status != http.StatusOK || len(d) != 0 || time.Since(start) > time.Second {
		t.Fatalf("%d %q after %v", status, d, time.Since(start))
	}
}

// waitHeld waits until the service holds n envelopes a device may read.
func waitHeld(t *testing.T, st *store.Store, home string, key appwire.KeyPair, n int) {
	t.Helper()
	waitFor(t, "the box's envelopes", func() bool {
		x, err := st.For(store.Principal{Kind: store.Device, Home: home, DeviceKey: key.Public()})
		if err != nil {
			return false
		}
		snap, _ := x.Snapshot()
		return len(snap.Envelopes) >= n
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 3 s for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
