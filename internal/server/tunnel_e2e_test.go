package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The tunnel through the whole service, as ftwcloudd wires it: a box that
// takes tun, phones on /v1/app, and each phone's own Noise session with the
// box riding inside, which the service routes and cannot read.

// sessionPrologue is the box session's prologue, spelled here on its own as
// a check on the box's spelling (appuplink.prologue in srcfl/ftw).
func sessionPrologue(boxStatic []byte) []byte {
	return append([]byte("ftw.session.v1:"), boxStatic...)
}

// tunBox is a box that links for its phones: caps with tun, a roster, and
// the box's half of each phone's session.
type tunBox struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	home   string
	static appwire.KeyPair
	conn   *websocket.Conn
	wmu    sync.Mutex
	seq    uint64

	mu       sync.Mutex
	allowed  map[string][]byte // device id to key, from the box's roster
	code     []byte
	sessions map[string]*boxSide
	gotDevs  []string
	ends     []cloudwire.Tun
	heard    []string
	purged   chan cloudwire.Purged
	closed   chan struct{}
}

type boxSide struct {
	sid uint32
	tr  *appwire.Transport
}

func (s *stack) connectTunBox() *tunBox {
	s.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	static, _ := appwire.GenerateKeyPair()
	b := &tunBox{t: s.t, key: key, home: cloudwire.HomeID(pk), static: static, allowed: map[string][]byte{},
		sessions: map[string]*boxSide{}, purged: make(chan cloudwire.Purged, 4), closed: make(chan struct{})}
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
	var ch cloudwire.Challenge
	if env := b.read(); env.T != cloudwire.MsgChallenge || cloudwire.Unmarshal(env.B, &ch) != nil {
		s.t.Fatalf("first message %q", env.T)
	}
	b.send(cloudwire.MsgHello, cloudwire.Hello{Header: b.header(), V: cloudwire.Version, PK: pk, Nonce: ch.Nonce,
		EKM: ekm, BoxNonce: bytes.Repeat([]byte{4}, cloudwire.NonceBytes), Build: "e2e", Clock: cloudwire.ClockNTP,
		Caps: []string{cloudwire.MsgRoster, cloudwire.CapTun}, RosterSeq: 1})
	if env := b.read(); env.T != cloudwire.MsgHelloOK {
		s.t.Fatalf("second message %q, want hello_ok", env.T)
	}
	go b.serve()
	return b
}

func (b *tunBox) header() cloudwire.Header {
	b.seq++
	return cloudwire.Header{Seq: b.seq, Boot: bytes.Repeat([]byte{0xb1}, cloudwire.BootBytes), UptimeMs: int64(b.seq)}
}

func (b *tunBox) read() cloudwire.Envelope {
	b.t.Helper()
	_ = b.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg, err := b.conn.ReadMessage()
	if err != nil {
		b.t.Fatal(err)
	}
	payload, _ := cloudwire.DecodeFrame(msg)
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil {
		b.t.Fatal(err)
	}
	return env
}

func (b *tunBox) write(env cloudwire.Envelope) {
	raw, _ := env.Encode()
	frame, _ := cloudwire.EncodeFrame(raw)
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_ = b.conn.WriteMessage(websocket.BinaryMessage, frame)
}

func (b *tunBox) send(t string, body any) {
	env, err := cloudwire.Seal(b.key, b.home, t, body)
	if err != nil {
		b.t.Fatal(err)
	}
	b.write(env)
}

func (b *tunBox) tun(t cloudwire.Tun) {
	body, _ := cloudwire.Marshal(t)
	b.write(cloudwire.Envelope{T: cloudwire.MsgTun, B: body})
}

// roster lists phones that may open a tunnel, the readable copy off, and
// the hash of a pairing code when one is on the screen.
func (b *tunBox) roster(seq uint64, grant cloudwire.Grant, code []byte, keys ...[]byte) {
	b.mu.Lock()
	b.code = code
	r := cloudwire.Roster{Header: b.header(), RosterSeq: seq, TTLS: 86_400, Grant: grant}
	for _, k := range keys {
		id := cloudwire.DeviceID(k)
		b.allowed[id] = k
		r.Devices = append(r.Devices, cloudwire.Device{ID: id, Key: k, Role: "owner", Scopes: protocol.CloudScopes, Epoch: 1, Tun: true})
	}
	if code != nil {
		r.Pending = []cloudwire.Pending{{Hash: cloudwire.PairingHash(b.home, code), TTLS: 600}}
	}
	b.mu.Unlock()
	sort.Slice(r.Devices, func(i, j int) bool { return r.Devices[i].ID < r.Devices[j].ID })
	b.send(cloudwire.MsgRoster, r)
}

var grantOff = cloudwire.Grant{Scopes: []string{}, Purposes: []string{}, Controller: cloudwire.ControllerSourceful}

// serve is the box: it answers each phone's handshake for a key its roster
// lists, or with the code on its screen, and answers every cmd with an ack
// and a result.
func (b *tunBox) serve() {
	defer close(b.closed)
	for {
		_ = b.conn.SetReadDeadline(time.Time{})
		_, msg, err := b.conn.ReadMessage()
		if err != nil {
			return
		}
		payload, _ := cloudwire.DecodeFrame(msg)
		env, err := cloudwire.DecodeEnvelope(payload)
		if err != nil {
			b.t.Errorf("service frame: %v", err)
			return
		}
		b.mu.Lock()
		b.heard = append(b.heard, env.T)
		b.mu.Unlock()
		switch env.T {
		case cloudwire.MsgPurged:
			var p cloudwire.Purged
			_ = cloudwire.Unmarshal(env.B, &p)
			b.purged <- p
		case cloudwire.MsgTun:
			var t cloudwire.Tun
			if len(env.Sig) != 0 || cloudwire.Unmarshal(env.B, &t) != nil {
				b.t.Error("a tun the box cannot read")
				return
			}
			b.inner(t)
		}
	}
}

func (b *tunBox) inner(t cloudwire.Tun) {
	b.mu.Lock()
	b.gotDevs = append(b.gotDevs, t.Dev)
	if t.Ended() {
		b.ends = append(b.ends, t)
		delete(b.sessions, t.Dev)
		b.mu.Unlock()
		return
	}
	side := b.sessions[t.Dev]
	b.mu.Unlock()
	if side != nil && side.sid == t.Sid {
		frame, err := side.tr.Decrypt(t.D)
		if err != nil {
			return
		}
		f, err := appwire.DecodeFrame(frame)
		if err != nil || f.Envelope.T != protocol.MsgCmd {
			return
		}
		var cmd protocol.Cmd
		_ = protocol.Unmarshal(f.Envelope.B, &cmd)
		for _, out := range []struct {
			t    string
			body any
		}{
			{protocol.MsgCmdAck, protocol.CmdAck{CmdID: cmd.CmdID, LeaseID: "lease-1", ExpiresAtMs: 60_000}},
			{protocol.MsgCmdResult, protocol.CmdResult{CmdID: cmd.CmdID, State: protocol.CmdApplied}},
		} {
			raw, _ := appwire.MarshalBody(out.body)
			reply, _ := appwire.EncodeFrame(appwire.Frame{Lane: appwire.LaneControl, Bucket: 512,
				Envelope: appwire.Envelope{T: out.t, B: raw}})
			d, _ := side.tr.Encrypt(reply)
			b.tun(cloudwire.Tun{Dev: t.Dev, Sid: t.Sid, D: d})
		}
		return
	}
	hs, err := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: b.static, Prologue: sessionPrologue(b.static.Public())})
	if err != nil {
		return
	}
	code, err := hs.ReadMessage(t.D)
	if err != nil {
		b.tun(cloudwire.Tun{Dev: t.Dev, Sid: t.Sid})
		return
	}
	b.mu.Lock()
	known := bytes.Equal(b.allowed[t.Dev], hs.RemoteStatic())
	paired := len(code) > 0 && bytes.Equal(code, b.code) && cloudwire.DeviceID(hs.RemoteStatic()) == t.Dev
	b.mu.Unlock()
	if !known && !paired {
		return
	}
	reply, _ := hs.WriteMessage(nil)
	keys, _ := hs.Split()
	b.mu.Lock()
	b.sessions[t.Dev] = &boxSide{sid: t.Sid, tr: appwire.NewTransport(keys)}
	b.mu.Unlock()
	b.tun(cloudwire.Tun{Dev: t.Dev, Sid: t.Sid, D: reply})
}

func (b *tunBox) devsSeen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.gotDevs...)
}

func (b *tunBox) endsSeen() []cloudwire.Tun {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]cloudwire.Tun(nil), b.ends...)
}

// tunPhone is a phone: its app session with the service, and inside it its
// own session with the box.
type tunPhone struct {
	t     *testing.T
	key   appwire.KeyPair
	conn  *websocket.Conn
	tr    *appwire.Transport
	snap  cloudwire.Snapshot
	inner *appwire.Transport
	in    *appwire.InitiatorState
	tuns  chan cloudwire.AppTun
	code  int
}

// dialPhone opens the app session. A refusal comes back as code, before
// message 2.
func (s *stack) dialPhone(home string, key appwire.KeyPair, now cloudwire.Now, origin string) *tunPhone {
	s.t.Helper()
	p := &tunPhone{t: s.t, key: key, tuns: make(chan cloudwire.AppTun, 64)}
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	conn, resp, err := d.Dial(strings.Replace(s.srv.URL, "https://", "wss://", 1)+"/v1/app?home="+home, h)
	if err != nil {
		if resp != nil {
			p.code = resp.StatusCode
		}
		return p
	}
	s.t.Cleanup(func() { _ = conn.Close() })
	p.conn = conn
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: key, RemoteStatic: s.noise.Public(),
		Prologue: cloudwire.AppPrologue(home)})
	if err != nil {
		s.t.Fatal(err)
	}
	payload, _ := cloudwire.Unsigned(cloudwire.MsgNow, now)
	msg1, _ := init.WriteMessage(payload)
	_ = conn.WriteMessage(websocket.BinaryMessage, msg1)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, msg2, err := conn.ReadMessage()
	if err != nil {
		var ce *websocket.CloseError
		if ok := asClose(err, &ce); ok {
			p.code = ce.Code
		}
		return p
	}
	reply, err := init.ReadMessage(msg2)
	if err != nil {
		s.t.Fatal(err)
	}
	if p.snap, err = cloudwire.ParseSnapshot(reply); err != nil {
		s.t.Fatal(err)
	}
	keys, _ := init.Split()
	p.tr = appwire.NewTransport(keys)
	go func() {
		for {
			_ = conn.SetReadDeadline(time.Time{})
			_, msg, err := conn.ReadMessage()
			if err != nil {
				close(p.tuns)
				return
			}
			frame, err := p.tr.Decrypt(msg)
			if err != nil {
				continue
			}
			payload, _ := cloudwire.DecodeFrame(frame)
			env, _ := cloudwire.DecodeEnvelope(payload)
			if env.T == cloudwire.MsgTun {
				var t cloudwire.AppTun
				_ = cloudwire.Unmarshal(env.B, &t)
				p.tuns <- t
			}
		}
	}()
	return p
}

func asClose(err error, ce **websocket.CloseError) bool {
	c, ok := err.(*websocket.CloseError)
	*ce = c
	return ok
}

// sendRaw sends any body as a tun envelope, as a phone might shape it.
func (p *tunPhone) sendRaw(body any) {
	p.t.Helper()
	env, _ := cloudwire.Unsigned(cloudwire.MsgTun, body)
	frame, _ := cloudwire.EncodeFrame(env)
	msg, _ := p.tr.Encrypt(frame)
	if err := p.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		p.t.Fatal(err)
	}
}

func (p *tunPhone) next() cloudwire.AppTun {
	p.t.Helper()
	select {
	case t, ok := <-p.tuns:
		if !ok {
			p.t.Fatal("the app session closed")
		}
		return t
	case <-time.After(3 * time.Second):
		p.t.Fatal("no tun reached the phone")
		return cloudwire.AppTun{}
	}
}

// boxMessage1 starts the phone's session with the box.
func (p *tunPhone) boxMessage1(boxStatic, code []byte) []byte {
	p.t.Helper()
	in, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: p.key, RemoteStatic: boxStatic,
		Prologue: sessionPrologue(boxStatic)})
	if err != nil {
		p.t.Fatal(err)
	}
	p.in = in
	m1, _ := in.WriteMessage(code)
	return m1
}

func (p *tunPhone) boxMessage2(d []byte) {
	p.t.Helper()
	if _, err := p.in.ReadMessage(d); err != nil {
		p.t.Fatal(err)
	}
	keys, _ := p.in.Split()
	p.inner = appwire.NewTransport(keys)
}

// open runs the box session through the tunnel.
func (p *tunPhone) open(boxStatic []byte, sid uint32, code []byte) {
	p.t.Helper()
	p.sendRaw(cloudwire.AppTun{Sid: sid, D: p.boxMessage1(boxStatic, code)})
	reply := p.next()
	if reply.Sid != sid || len(reply.D) == 0 {
		p.t.Fatalf("the box answered %+v", reply)
	}
	p.boxMessage2(reply.D)
}

// cmd sends a command inside the box session and returns the states of the
// ack and result.
func (p *tunPhone) cmd(sid uint32, id string) (string, string) {
	p.t.Helper()
	raw, _ := appwire.MarshalBody(protocol.Cmd{CmdID: id, Op: "mode.set", Args: map[string]any{"mode": "self_consumption"},
		NotValidAfterMs: 60_000, Expect: protocol.Expect{Rev: 1}})
	frame, _ := appwire.EncodeFrame(appwire.Frame{Lane: appwire.LaneControl, Bucket: 512,
		Envelope: appwire.Envelope{T: protocol.MsgCmd, B: raw}})
	d, _ := p.inner.Encrypt(frame)
	p.sendRaw(cloudwire.AppTun{Sid: sid, D: d})
	var ack, res string
	for ack == "" || res == "" {
		t := p.next()
		plain, err := p.inner.Decrypt(t.D)
		if err != nil {
			p.t.Fatal(err)
		}
		f, _ := appwire.DecodeFrame(plain)
		switch f.Envelope.T {
		case protocol.MsgCmdAck:
			ack = f.Envelope.T
		case protocol.MsgCmdResult:
			var r protocol.CmdResult
			_ = protocol.Unmarshal(f.Envelope.B, &r)
			res = r.State
		}
	}
	return ack, res
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("never: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A phone the roster lists sends a command through the service and gets the
// box's answer, with the readable copy off. Nothing to read is held.
func TestACommandThroughTheServiceGetsTheBoxsAnswer(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	// A reading the box sends anyway is not kept: the copy is off.
	box.send(cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1}, Ages: map[string]int64{}})

	var phone *tunPhone
	eventually(t, "the phone is admitted", func() bool {
		phone = s.dialPhone(box.home, key, cloudwire.Now{Hz: 1}, "")
		return phone.conn != nil && phone.tr != nil
	})
	if len(phone.snap.Envelopes) != 0 {
		t.Fatalf("the snapshot holds %d envelopes with the copy off", len(phone.snap.Envelopes))
	}
	phone.open(box.static.Public(), 7, nil)

	var took []time.Duration
	for i := range 20 {
		start := time.Now()
		ack, res := phone.cmd(7, "0192f2a0-7c1e-7000-8000-0000000000"+string(rune('a'+i))+"0")
		took = append(took, time.Since(start))
		if ack != protocol.MsgCmdAck || res != protocol.CmdApplied {
			t.Fatalf("ack %q, result %q", ack, res)
		}
	}
	sort.Slice(took, func(a, b int) bool { return took[a] < took[b] })
	t.Logf("cmd to result through ftwcloudd, 20 runs: median %s, max %s", took[10], took[19])
	for _, d := range box.devsSeen() {
		if d != cloudwire.DeviceID(key.Public()) {
			t.Fatalf("the box got a tun under %q", d)
		}
	}
}

// The box session's message 1 may ride in the app session's message 1, and
// the box's answer follows message 2.
func TestTheBoxSessionRidesInMessage1(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	waitRoster(t, s, box.home, key)
	p := &tunPhone{t: t, key: key}
	m1 := p.boxMessage1(box.static.Public(), nil)
	phone := s.dialPhone(box.home, key, cloudwire.Now{Hz: 1, Tun: &cloudwire.AppTun{Sid: 3, D: m1}}, "")
	if phone.tr == nil {
		t.Fatalf("refused with %d", phone.code)
	}
	phone.in = p.in
	reply := phone.next()
	if reply.Sid != 3 || len(reply.D) == 0 {
		t.Fatalf("the box answered %+v", reply)
	}
	phone.boxMessage2(reply.D)
	if ack, res := phone.cmd(3, "0192f2a0-7c1e-7000-8000-00000000e001"); ack == "" || res != protocol.CmdApplied {
		t.Fatalf("ack %q result %q", ack, res)
	}
}

func waitRoster(t *testing.T, s *stack, home string, key appwire.KeyPair) {
	t.Helper()
	eventually(t, "the roster lists the phone", func() bool {
		p := s.dialPhone(home, key, cloudwire.Now{}, "")
		if p.conn != nil {
			_ = p.conn.Close()
		}
		return p.tr != nil
	})
}

// A key the roster does not list is refused before message 2, and nothing
// it sent reaches the box.
func TestAPhoneNotInTheRosterIsRefusedBeforeAnythingIsForwarded(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	known, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, known.Public())
	waitRoster(t, s, box.home, known)

	stranger, _ := appwire.GenerateKeyPair()
	p := &tunPhone{t: t, key: stranger}
	m1 := p.boxMessage1(box.static.Public(), nil)
	phone := s.dialPhone(box.home, stranger, cloudwire.Now{Hz: 1, Tun: &cloudwire.AppTun{Sid: 1, D: m1}}, "")
	if phone.tr != nil || phone.code != cloudwire.CloseDenied {
		t.Fatalf("a stranger got a session (code %d)", phone.code)
	}
	time.Sleep(200 * time.Millisecond)
	if devs := box.devsSeen(); len(devs) != 0 {
		t.Fatalf("the box got tun from %v", devs)
	}
}

// The service names the device by the key its own handshake proved. A dev a
// phone puts in its tun is ignored.
func TestAForgedDevIsIgnored(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	mine, _ := appwire.GenerateKeyPair()
	other, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, mine.Public(), other.Public())
	waitRoster(t, s, box.home, mine)
	phone := s.dialPhone(box.home, mine, cloudwire.Now{Hz: 1}, "")
	phone.sendRaw(map[string]any{"dev": cloudwire.DeviceID(other.Public()), "sid": 5,
		"d": phone.boxMessage1(box.static.Public(), nil)})
	reply := phone.next()
	if reply.Sid != 5 || len(reply.D) == 0 {
		t.Fatalf("the box answered %+v", reply)
	}
	for _, d := range box.devsSeen() {
		if d != cloudwire.DeviceID(mine.Public()) {
			t.Fatalf("the box got a tun under %q, the forged id", d)
		}
	}
}

// With the readable copy withdrawn, the service drops what it held, signs a
// receipt for the grant, and the tunnel still works.
func TestTheCopyStaysOffWhileTheTunnelWorks(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	key, _ := appwire.GenerateKeyPair()
	grantID := bytes.Repeat([]byte{7}, cloudwire.GrantIDBytes)
	on := cloudwire.Grant{ID: grantID, Scopes: []string{protocol.ScopeLiveRead},
		Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}
	box.roster(2, on, nil, key.Public())
	box.send(cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1}, Ages: map[string]int64{}})
	eventually(t, "the copy is held", func() bool {
		p := s.dialPhone(box.home, key, cloudwire.Now{}, "")
		if p.conn != nil {
			_ = p.conn.Close()
		}
		return len(p.snap.Envelopes) == 1
	})

	withdrawn := cloudwire.Grant{ID: grantID, Scopes: []string{}, Purposes: []string{}, Controller: cloudwire.ControllerSourceful}
	box.roster(3, withdrawn, nil, key.Public())
	select {
	case p := <-box.purged:
		if p.What != cloudwire.PurgedCopy || !bytes.Equal(p.GrantID, grantID) {
			t.Fatalf("receipt %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no receipt for the withdrawn copy")
	}
	box.send(cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 2}, Ages: map[string]int64{}})
	phone := s.dialPhone(box.home, key, cloudwire.Now{Hz: 1}, "")
	if phone.tr == nil || len(phone.snap.Envelopes) != 0 {
		t.Fatalf("after the receipt: code %d, %d envelopes", phone.code, len(phone.snap.Envelopes))
	}
	phone.open(box.static.Public(), 1, nil)
	if _, res := phone.cmd(1, "0192f2a0-7c1e-7000-8000-00000000f001"); res != protocol.CmdApplied {
		t.Fatalf("result %q", res)
	}
}

// A new phone pairs through the service: the roster lists the code's hash,
// the phone proves it once, and its session stays open when the roster
// lists it.
func TestAPhonePairsThroughTheService(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	owner, _ := appwire.GenerateKeyPair()
	code := bytes.Repeat([]byte{0x42}, 16)
	box.roster(2, grantOff, code, owner.Public())
	waitRoster(t, s, box.home, owner)

	newKey, _ := appwire.GenerateKeyPair()
	if p := s.dialPhone(box.home, newKey, cloudwire.Now{Hz: 1}, ""); p.tr != nil {
		t.Fatal("a new phone without the code was admitted")
	}
	if p := s.dialPhone(box.home, newKey, cloudwire.Now{Pair: cloudwire.PairingHash(box.home, []byte("wrong-code-000000"))}, ""); p.tr != nil {
		t.Fatal("a wrong pairing hash was admitted")
	}
	phone := s.dialPhone(box.home, newKey, cloudwire.Now{Hz: 1, Pair: cloudwire.PairingHash(box.home, code)}, "")
	if phone.tr == nil {
		t.Fatalf("the pairing phone was refused with %d", phone.code)
	}
	phone.open(box.static.Public(), 1, code)
	if devs := box.devsSeen(); devs[len(devs)-1] != cloudwire.DeviceID(newKey.Public()) {
		t.Fatalf("the box got the pairing under %v", devs)
	}
	// The hash admits one handshake.
	again, _ := appwire.GenerateKeyPair()
	if p := s.dialPhone(box.home, again, cloudwire.Now{Pair: cloudwire.PairingHash(box.home, code)}, ""); p.tr != nil {
		t.Fatal("a pairing hash admitted a second phone")
	}
	// The box paired it: the roster lists it, and the session stays.
	box.roster(3, grantOff, nil, owner.Public(), newKey.Public())
	time.Sleep(200 * time.Millisecond)
	if _, res := phone.cmd(1, "0192f2a0-7c1e-7000-8000-00000000a0a1"); res != protocol.CmdApplied {
		t.Fatalf("result %q after the roster listed the phone", res)
	}
}

// The ends: a phone that leaves ends its box session at the box, and a box
// that goes ends the phone's.
func TestEachEndHearsTheOtherGo(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	a, _ := appwire.GenerateKeyPair()
	b, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, a.Public(), b.Public())
	waitRoster(t, s, box.home, a)

	leaving := s.dialPhone(box.home, a, cloudwire.Now{Hz: 1}, "")
	leaving.open(box.static.Public(), 4, nil)
	_ = leaving.conn.Close()
	eventually(t, "the box hears the phone left", func() bool {
		for _, e := range box.endsSeen() {
			if e.Dev == cloudwire.DeviceID(a.Public()) && e.Sid == 4 {
				return true
			}
		}
		return false
	})

	staying := s.dialPhone(box.home, b, cloudwire.Now{Hz: 1}, "")
	staying.open(box.static.Public(), 9, nil)
	_ = box.conn.Close()
	end := staying.next()
	if end.Sid != 9 || len(end.D) != 0 {
		t.Fatalf("after the box went the phone got %+v", end)
	}
	// With no box, a new session is ended at once.
	staying.sendRaw(cloudwire.AppTun{Sid: 10, D: staying.boxMessage1(box.static.Public(), nil)})
	if end := staying.next(); end.Sid != 10 || len(end.D) != 0 {
		t.Fatalf("with no box the phone got %+v", end)
	}
}

// Browsers: the web app's origin is let in, any other is refused.
func TestOnlyTheWebAppsOriginIsLetIn(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	waitRoster(t, s, box.home, key)
	if p := s.dialPhone(box.home, key, cloudwire.Now{}, "https://evil.example"); p.conn != nil {
		t.Fatal("another origin was let in")
	}
	if p := s.dialPhone(box.home, key, cloudwire.Now{}, "https://app.ftw.energy"); p.tr == nil {
		t.Fatalf("the web app's origin was refused: %d", p.code)
	}
}
