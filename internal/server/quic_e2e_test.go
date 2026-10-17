package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/srcfl/ftw-cloud/internal/quicdoor"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/wire"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The uplink and the app session over QUIC, through the whole service as
// ftwcloudd wires it: the same handlers as the WebSockets, a control stream,
// a bulk stream for the tunnel's lane 1, and datagrams for hb and live.

// quic starts the stack's QUIC door, with the uplink and the app session
// served by the stack's own handlers, and returns its address.
func (s *stack) quic() string {
	s.t.Helper()
	if s.quicAddr != "" {
		return s.quicAddr
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatal(err)
	}
	door := quicdoor.New(s.srv.Config.Handler, nil)
	s.door = door
	door.Box = func(c *quicdoor.Conn, ekm []byte) { s.up.ServeConn(c, ekm) }
	door.App = func(c *quicdoor.Conn, home string) { s.app.ServeConn(c, home) }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = door.Serve(ctx, pc, &tls.Config{Certificates: s.srv.TLS.Certificates})
	}()
	s.t.Cleanup(func() {
		cancel()
		<-done
	})
	s.quicAddr = pc.LocalAddr().String()
	return s.quicAddr
}

func (s *stack) clientTLS() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
}

// dialQUIC opens a client connection to the stack's door.
func (s *stack) dialQUIC(alpn, target string) (*quicdoor.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return quicdoor.Dial(ctx, s.quic(), s.clientTLS(), alpn, target, nil)
}

// connectTunBoxQUIC is connectTunBox over QUIC.
func (s *stack) connectTunBoxQUIC() *tunBox {
	s.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	static, _ := appwire.GenerateKeyPair()
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	b := &tunBox{t: s.t, key: key, home: cloudwire.HomeID(pk), static: static, allowed: map[string][]byte{},
		sessions: map[string]*boxSide{}, purged: make(chan cloudwire.Purged, 4), closed: make(chan struct{})}
	conn, err := s.dialQUIC(cloudwire.ALPNBox, cloudwire.TargetBox)
	if err != nil {
		s.t.Fatal(err)
	}
	ekm, err := conn.Exporter()
	if err != nil {
		s.t.Fatal(err)
	}
	b.link(conn, ekm)
	return b
}

// dialPhoneQUIC is dialPhone over QUIC.
func (s *stack) dialPhoneQUIC(home string, key appwire.KeyPair, now cloudwire.Now) *tunPhone {
	s.t.Helper()
	p := newTunPhone(s.t, key)
	conn, err := s.dialQUIC(cloudwire.ALPNApp, cloudwire.AppTarget(home))
	if err != nil {
		s.t.Fatal(err)
	}
	p.session(conn, s.noise.Public(), home, now)
	return p
}

// say sends the service one message of the app session.
func (p *tunPhone) say(t string, body any) {
	p.t.Helper()
	env, _ := cloudwire.Unsigned(t, body)
	frame, _ := cloudwire.EncodeFrame(env)
	msg, _ := p.tr.Encrypt(frame)
	if err := p.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		p.t.Fatal(err)
	}
}

func (p *tunPhone) kindsOf(t string) []int {
	p.kmu.Lock()
	defer p.kmu.Unlock()
	return slices.Clone(p.kinds[t])
}

// A command crosses the service over QUIC on both legs, and over QUIC on one
// leg and a WebSocket on the other: the handlers are the same.
func TestACommandCrossesQUIC(t *testing.T) {
	for _, legs := range []struct {
		name     string
		boxQUIC  bool
		phoneQUI bool
	}{{"both QUIC", true, true}, {"box QUIC, phone WebSocket", true, false}, {"box WebSocket, phone QUIC", false, true}} {
		t.Run(legs.name, func(t *testing.T) {
			s := newStack(t)
			var box *tunBox
			if legs.boxQUIC {
				box = s.connectTunBoxQUIC()
			} else {
				box = s.connectTunBox()
			}
			key, _ := appwire.GenerateKeyPair()
			box.roster(2, grantOff, nil, key.Public())
			eventually(t, "the roster held", func() bool {
				_, err := s.st.For(storePrincipal(box.home, key))
				return err == nil
			})
			var phone *tunPhone
			if legs.phoneQUI {
				phone = s.dialPhoneQUIC(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking})
			} else {
				phone = s.dialPhone(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking}, "")
			}
			if phone.tr == nil {
				t.Fatalf("the app session did not open: %d", phone.code)
			}
			phone.open(box.static.Public(), 7, nil)
			if ack, res := phone.cmd(7, "c1"); ack != protocol.MsgCmdAck || res != protocol.CmdApplied {
				t.Fatalf("over %s: ack %q, result %q", legs.name, ack, res)
			}
		})
	}
}

// The box's bulk stream reaches the phone's: a lane 1 frame of the phone's
// session never waits behind lane 0 or holds it up. Lane 0 stays on the
// control stream.
func TestBulkTravelsOnTheBulkStream(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	phone := s.dialPhoneQUIC(box.home, key, cloudwire.Now{})
	if phone.tr == nil {
		t.Fatalf("the app session did not open: %d", phone.code)
	}
	phone.open(box.static.Public(), 9, nil)
	dev := cloudwire.DeviceID(key.Public())

	bulk := bytes.Repeat([]byte{0xb7}, 4096+appwire.TransportOverhead)
	body, _ := cloudwire.Marshal(cloudwire.Tun{Dev: dev, Sid: 9, D: bulk})
	box.writeAs(wire.Bulk, cloudwire.Envelope{T: cloudwire.MsgTun, B: body})
	got := phone.next()
	if !bytes.Equal(got.D, bulk) {
		t.Fatalf("bulk arrived as %d bytes", len(got.D))
	}
	kinds := phone.kindsOf(cloudwire.MsgTun)
	// The box's answer to message 1 came on the control stream, the bulk
	// frame on the bulk stream.
	if !slices.Equal(kinds, []int{websocket.BinaryMessage, wire.Bulk}) {
		t.Fatalf("tun kinds at the phone: %v", kinds)
	}

	// Anything but a tun on the bulk stream breaks the protocol.
	box.writeAs(wire.Bulk, mustSeal(t, box, cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP}))
	waitClosed(t, box)
}

// With the readable copy on, hb and a live without sources reach the phone
// as datagrams; a live that carries its source table comes on the stream.
func TestHbAndLiveTravelAsDatagrams(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantServe, nil, key.Public())
	phone := s.dialPhoneQUIC(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking})
	if phone.tr == nil {
		t.Fatalf("the app session did not open: %d", phone.code)
	}

	full := cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1800}, SrcRev: 1, Ages: map[string]int64{"m": 300},
		Sources:      map[string]cloudwire.Source{"m": {Kind: "driver", State: protocol.SourceLive, StaleAfterMs: 10_000}},
		FieldSources: map[string][]string{"2": {"m"}}}
	box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgLive, full))
	// A live with its table may not go as a datagram: the uplink closes.
	waitClosed(t, box)

	box = s.connectTunBoxQUICAs(box.key, box.static)
	box.roster(3, grantServe, nil, key.Public())
	box.send(cloudwire.MsgLive, full)
	box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgLive,
		cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1900}, SrcRev: 1, Ages: map[string]int64{"m": 100}}))
	box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP, SrcRev: 1}))

	phone = s.dialPhoneQUIC(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking})
	if phone.tr == nil {
		t.Fatalf("the app session did not open again: %d", phone.code)
	}
	// Until the phone speaks, it may not hold message 2 yet: everything
	// comes on the control stream, behind it.
	box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP, SrcRev: 1}))
	eventually(t, "an hb before the phone spoke", func() bool { return len(phone.kindsOf(cloudwire.MsgHB)) >= 1 })
	if hb := phone.kindsOf(cloudwire.MsgHB); hb[0] != websocket.BinaryMessage {
		t.Fatalf("before the phone spoke, an hb came as %d", hb[0])
	}
	phone.say(cloudwire.MsgWatch, cloudwire.Watch{Hz: cloudwire.HzLooking})
	// Observing a datagram proves the phone's watch was processed. A sleep
	// does not order the independent control stream and datagram path.
	eventually(t, "an hb datagram after the phone spoke", func() bool {
		if slices.Contains(phone.kindsOf(cloudwire.MsgHB), wire.Datagram) {
			return true
		}
		box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP, SrcRev: 1}))
		return false
	})
	eventually(t, "a live datagram before the later source table", func() bool {
		if len(phone.kindsOf(cloudwire.MsgLive)) > 0 {
			return true
		}
		box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgLive,
			cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 2000}, SrcRev: 1, Ages: map[string]int64{"m": 50}}))
		return false
	})
	box.send(cloudwire.MsgLive, full2(box))
	eventually(t, "two lives and an hb at the phone", func() bool {
		return len(phone.kindsOf(cloudwire.MsgLive)) >= 2 && len(phone.kindsOf(cloudwire.MsgHB)) >= 1
	})
	lives := phone.kindsOf(cloudwire.MsgLive)
	if lives[0] != wire.Datagram || lives[len(lives)-1] != websocket.BinaryMessage {
		t.Fatalf("live kinds at the phone: %v", lives)
	}
	if hb := phone.kindsOf(cloudwire.MsgHB); hb[len(hb)-1] != wire.Datagram {
		t.Fatalf("hb kinds at the phone: %v", hb)
	}
}

// A datagram that arrives after a later message of its class is dropped:
// the service never holds an older reading than it has.
func TestALateDatagramIsDropped(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantServe, nil, key.Public())
	early := mustSeal(t, box, cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1}, SrcRev: 1, Ages: map[string]int64{}})
	box.send(cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 2}, SrcRev: 1, Ages: map[string]int64{}})
	box.writeAs(wire.Datagram, early)
	box.send(cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP, SrcRev: 1})
	waitHeldN(t, s, box.home, key, 2)
	snap := heldSnapshot(t, s, box.home, key)
	for _, raw := range snap.Envelopes {
		env, _ := cloudwire.DecodeEnvelope(raw)
		if env.T != cloudwire.MsgLive {
			continue
		}
		var l cloudwire.Live
		_ = cloudwire.Unmarshal(env.B, &l)
		if l.Fields["2"] != 2 {
			t.Fatalf("the service holds the late live: %v", l.Fields)
		}
	}
}

// Over QUIC a live without its table can overtake the one that carries it.
// The service still takes the late table, and keeps the newer values: a
// phone's snapshot holds both, so its sources do not go stale for want of a
// table.
func TestALateTableStillCounts(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantServe, nil, key.Public())
	table := map[string]cloudwire.Source{"m": {Kind: "driver", State: protocol.SourceLive, StaleAfterMs: 10_000}}
	box.send(cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 1}, Sources: table, SrcRev: 1, Ages: map[string]int64{}})
	// The grant and first table must arrive before the overtaking datagram.
	waitHeldN(t, s, box.home, key, 1)
	withTable := mustSeal(t, box, cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 2},
		Sources: table, FieldSources: map[string][]string{"2": {"m"}}, SrcRev: 2, Ages: map[string]int64{}})
	box.writeAs(wire.Datagram, mustSeal(t, box, cloudwire.MsgLive, cloudwire.Live{Header: box.header(), Fields: map[string]int64{"2": 3}, SrcRev: 2, Ages: map[string]int64{}}))
	eventually(t, "the overtaking live held before its late table", func() bool {
		for _, raw := range heldSnapshot(t, s, box.home, key).Envelopes {
			env, _ := cloudwire.DecodeEnvelope(raw)
			if env.T != cloudwire.MsgLive {
				continue
			}
			var live cloudwire.Live
			if cloudwire.Unmarshal(env.B, &live) == nil && live.Fields["2"] == 3 {
				return true
			}
		}
		return false
	})
	box.writeAs(websocket.BinaryMessage, withTable)
	box.send(cloudwire.MsgHB, cloudwire.HB{Header: box.header(), Clock: cloudwire.ClockNTP, SrcRev: 2})
	waitHeldN(t, s, box.home, key, 3)
	var newest int64
	var tableRev uint64
	for _, raw := range heldSnapshot(t, s, box.home, key).Envelopes {
		env, _ := cloudwire.DecodeEnvelope(raw)
		if env.T != cloudwire.MsgLive {
			continue
		}
		var l cloudwire.Live
		_ = cloudwire.Unmarshal(env.B, &l)
		if l.Sources != nil {
			tableRev = max(tableRev, l.SrcRev)
		}
		newest = l.Fields["2"]
	}
	if tableRev != 2 {
		t.Fatalf("the service holds table %d, not the late one", tableRev)
	}
	if newest != 3 {
		t.Fatalf("the newest live in the snapshot holds %d, not the overtaking one's 3", newest)
	}
}

// The box binds hello to the TLS session inside QUIC. Its exporter is the
// service's, so hello_ok comes; one from another session closes the uplink.
func TestHelloOverQUICIsBoundToItsTLSSession(t *testing.T) {
	s := newStack(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	home := cloudwire.HomeID(pk)
	for _, bound := range []bool{true, false} {
		conn, err := s.dialQUIC(cloudwire.ALPNBox, cloudwire.TargetBox)
		if err != nil {
			t.Fatal(err)
		}
		ekm, _ := conn.Exporter()
		if !bound {
			ekm = bytes.Repeat([]byte{1}, cloudwire.EKMBytes)
		}
		b := &tunBox{t: t, key: key, home: home, conn: conn}
		var ch cloudwire.Challenge
		if env := b.read(); env.T != cloudwire.MsgChallenge || cloudwire.Unmarshal(env.B, &ch) != nil {
			t.Fatalf("first message %q", env.T)
		}
		b.send(cloudwire.MsgHello, cloudwire.Hello{Header: b.header(), V: cloudwire.Version, PK: pk, Nonce: ch.Nonce,
			EKM: ekm, BoxNonce: bytes.Repeat([]byte{4}, cloudwire.NonceBytes), Build: "e2e", Clock: cloudwire.ClockNTP,
			Caps: []string{cloudwire.MsgRoster}, RosterSeq: 1})
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, msg, err := conn.ReadMessage()
		if bound {
			payload, _ := cloudwire.DecodeFrame(msg)
			env, _ := cloudwire.DecodeEnvelope(payload)
			var ok cloudwire.HelloOK
			if err != nil || env.T != cloudwire.MsgHelloOK || cloudwire.Unmarshal(env.B, &ok) != nil || !bytes.Equal(ok.EKM, ekm) {
				t.Fatalf("a bound hello got %q, %v", env.T, err)
			}
		} else if err == nil {
			t.Fatal("a hello bound to another TLS session was answered")
		}
		_ = conn.Close()
	}
}

// A refusal crosses QUIC as the WebSocket's close code.
func TestARefusalOverQUICCarriesItsCode(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	stranger, _ := appwire.GenerateKeyPair()
	known, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, known.Public())
	phone := s.dialPhoneQUIC(box.home, stranger, cloudwire.Now{})
	if phone.tr != nil || phone.code != cloudwire.CloseDenied {
		t.Fatalf("a phone not in the roster: open %v, code %d", phone.tr != nil, phone.code)
	}
	conn, err := s.dialQUIC(cloudwire.ALPNApp, "/v1/app?home=not-a-home")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = conn.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != cloudwire.CloseProtocol {
		t.Fatalf("a bad home: %v", err)
	}
}

// A phone that opens a second stream, or a box that opens a second bulk
// stream, breaks the protocol.
func TestOneStreamOfEachKind(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	phone := s.dialPhoneQUIC(box.home, key, cloudwire.Now{})
	if phone.tr == nil {
		t.Fatal("the app session did not open")
	}
	str, err := phone.conn.(*quicdoor.Conn).QUIC().OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = str.Write(cloudwire.AppendMessage(nil, []byte("x")))
	select {
	case <-phone.conn.(*quicdoor.Conn).Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("a phone's unidirectional stream was let through")
	}

	qc := box.conn.(*quicdoor.Conn).QUIC()
	for range 2 {
		str, err := qc.OpenUniStream()
		if err != nil {
			t.Fatal(err)
		}
		_, _ = str.Write([]byte{0})
	}
	waitClosed(t, box)
}

// The phone moves to a new address mid-session, as from Wi-Fi to cellular:
// the QUIC connection follows, and the box session inside goes on with the
// same keys and sid. No handshake, no new tunnel.
func TestThePhoneSessionSurvivesANetworkSwitch(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	phone := s.dialPhoneQUIC(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking})
	if phone.tr == nil {
		t.Fatal("the app session did not open")
	}
	phone.open(box.static.Public(), 11, nil)
	if ack, _ := phone.cmd(11, "before"); ack != protocol.MsgCmdAck {
		t.Fatal("no ack before the switch")
	}
	qc := phone.conn.(*quicdoor.Conn).QUIC()
	before := qc.LocalAddr().String()
	handshakes := box.handshakes()

	// The new network: another UDP socket, so another source address.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close() })
	path, err := qc.AddPath(tr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := path.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := path.Switch(); err != nil {
		t.Fatal(err)
	}
	if ack, res := phone.cmd(11, "after"); ack != protocol.MsgCmdAck || res != protocol.CmdApplied {
		t.Fatalf("after the switch: ack %q, result %q", ack, res)
	}
	if after := qc.LocalAddr().String(); after == before || after != pc.LocalAddr().String() {
		t.Fatalf("the session runs from %s, was %s, the new network is %s", after, before, pc.LocalAddr())
	}
	if got := box.handshakes(); got != handshakes {
		t.Fatalf("the box ran %d handshakes across the switch", got-handshakes)
	}
}

var grantServe = cloudwire.Grant{ID: bytes.Repeat([]byte{8}, cloudwire.GrantIDBytes), Scopes: protocol.CloudScopes,
	Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}

// connectTunBoxQUICAs is the same box dialling again over QUIC.
func (s *stack) connectTunBoxQUICAs(key *ecdsa.PrivateKey, static appwire.KeyPair) *tunBox {
	s.t.Helper()
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	b := &tunBox{t: s.t, key: key, home: cloudwire.HomeID(pk), static: static, allowed: map[string][]byte{},
		sessions: map[string]*boxSide{}, purged: make(chan cloudwire.Purged, 4), closed: make(chan struct{})}
	conn, err := s.dialQUIC(cloudwire.ALPNBox, cloudwire.TargetBox)
	if err != nil {
		s.t.Fatal(err)
	}
	ekm, _ := conn.Exporter()
	b.link(conn, ekm)
	return b
}

func storePrincipal(home string, key appwire.KeyPair) store.Principal {
	return store.Principal{Kind: store.Device, Home: home, DeviceKey: key.Public()}
}

func mustSeal(t *testing.T, b *tunBox, typ string, body any) cloudwire.Envelope {
	t.Helper()
	env, err := cloudwire.Seal(b.key, b.home, typ, body)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// full2 is another live that carries its source table.
func full2(b *tunBox) cloudwire.Live {
	return cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 2100}, SrcRev: 1, Ages: map[string]int64{"m": 10},
		Sources:      map[string]cloudwire.Source{"m": {Kind: "driver", State: protocol.SourceLive, StaleAfterMs: 10_000}},
		FieldSources: map[string][]string{"2": {"m"}}}
}

// waitClosed waits for the service to end the box's uplink.
func waitClosed(t *testing.T, b *tunBox) {
	t.Helper()
	select {
	case <-b.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the uplink stayed open")
	}
}

func waitHeldN(t *testing.T, s *stack, home string, key appwire.KeyPair, n int) {
	t.Helper()
	waitHeld(t, s.st, home, key, n)
}

func heldSnapshot(t *testing.T, s *stack, home string, key appwire.KeyPair) store.Snapshot {
	t.Helper()
	x, err := s.st.For(storePrincipal(home, key))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := x.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snap
}
