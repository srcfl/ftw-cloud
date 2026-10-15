package uplink

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The service makes a connection the home's only after hello_ok has gone,
// so a phone that asks for one-second updates while a box connects can never
// put watch ahead of hello_ok. The box would close on it.
func TestNothingReachesABoxBeforeHelloOK(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				s.up.Watch(b.home)
				s.up.Tun(b.home, cloudwire.Tun{Dev: "x", Sid: 1, D: []byte{1}})
			}
		}
	}()
	for range 20 {
		// connect fails the test on anything but hello_ok after hello.
		if _, err := b.connect(s, nil); err != nil {
			t.Fatal(err)
		}
		_ = b.conn.Close()
	}
	close(stop)
	wg.Wait()
}

// After a restart the service holds every roster its boxes signed, and a
// home's phones are admitted before the box connects again. A roster that
// does not verify with the home's key is left out.
func TestRostersComeBackAfterARestart(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	wait(t, "the roster is stored", func() bool {
		h, ok, _ := s.reg.Get(b.home)
		return ok && h.Roster != nil
	})
	other := newBox(t)
	if _, err := other.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	other.send(cloudwire.MsgRoster, other.roster(protocol.ScopeLiveRead))
	wait(t, "the second roster is stored", func() bool {
		h, ok, _ := s.reg.Get(other.home)
		return ok && h.Roster != nil
	})
	// A roster in the file that its home's key did not sign.
	forged, _ := cloudwire.Seal(b.key, other.home, cloudwire.MsgRoster, other.roster(protocol.ScopeLiveRead))
	raw, _ := forged.Encode()
	if err := s.reg.SetRoster(other.home, 9, nil, raw, time.Now()); err != nil {
		t.Fatal(err)
	}

	fresh := store.New(nil)
	up := New(fresh, s.reg, s.key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	n, err := up.Restore()
	if err != nil || n != 1 {
		t.Fatalf("restored %d: %v", n, err)
	}
	if _, err := fresh.For(store.Principal{Kind: store.Device, Home: b.home, DeviceKey: ownerKey}); err != nil {
		t.Fatalf("a phone was refused after the restart: %v", err)
	}
	if _, err := fresh.For(store.Principal{Kind: store.Device, Home: other.home, DeviceKey: ownerKey}); err == nil {
		t.Fatal("a roster its home did not sign admitted a phone")
	}
}

// A roster's grant has three shapes, and nothing else passes: a copy on with
// serve, a withdrawn copy with its id alone, or none at all.
func TestARosterGrantHasThreeShapes(t *testing.T) {
	id := bytes.Repeat([]byte{5}, 16)
	for name, c := range map[string]struct {
		g  cloudwire.Grant
		ok bool
	}{
		"on":            {cloudwire.Grant{ID: id, Scopes: []string{protocol.ScopeLiveRead}, Purposes: []string{protocol.CloudPurposeServe}}, true},
		"withdrawn":     {cloudwire.Grant{ID: id}, true},
		"off":           {cloudwire.Grant{}, true},
		"scopes, no id": {cloudwire.Grant{Scopes: []string{protocol.ScopeLiveRead}}, false},
		"id and scopes": {cloudwire.Grant{ID: id, Scopes: []string{protocol.ScopeLiveRead}}, false},
		"a short id":    {cloudwire.Grant{ID: id[:8], Purposes: []string{protocol.CloudPurposeServe}}, false},
		"a write scope": {cloudwire.Grant{ID: id, Scopes: []string{protocol.ScopeDispatchWrite}, Purposes: []string{protocol.CloudPurposeServe}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			s := newService(t)
			b := newBox(t)
			if _, err := b.connect(s, nil); err != nil {
				t.Fatal(err)
			}
			c.g.Controller = cloudwire.ControllerSourceful
			r := b.roster()
			r.Grant = c.g
			b.send(cloudwire.MsgRoster, r)
			if closed := b.closed(); closed == c.ok {
				t.Fatalf("closed %v, want %v", closed, !c.ok)
			}
		})
	}
}

// tunBox connects a box that takes tun and lists one phone that may open a
// tunnel, with the readable copy off.
func tunConnect(t *testing.T, s *service) *box {
	t.Helper()
	b := newBox(t)
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	conn, _, err := d.Dial("wss://"+s.srv.Listener.Addr().String()+"/v1/box", nil)
	if err != nil {
		t.Fatal(err)
	}
	b.conn = conn
	t.Cleanup(func() { _ = conn.Close() })
	cs := conn.NetConn().(*tls.Conn).ConnectionState()
	ekm, _ := cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, 32)
	var ch cloudwire.Challenge
	_ = cloudwire.Unmarshal(b.read().B, &ch)
	b.send(cloudwire.MsgHello, cloudwire.Hello{Header: b.header(), V: 1, PK: b.pk, Nonce: ch.Nonce, EKM: ekm,
		BoxNonce: bytes.Repeat([]byte{4}, 32), Build: "test", Clock: cloudwire.ClockNTP,
		Caps: []string{cloudwire.MsgRoster, cloudwire.CapTun}})
	if env := b.read(); env.T != cloudwire.MsgHelloOK {
		t.Fatalf("got %q", env.T)
	}
	r := b.roster()
	r.Grant = cloudwire.Grant{Controller: cloudwire.ControllerSourceful}
	r.Devices[0].Tun = true
	b.send(cloudwire.MsgRoster, r)
	return b
}

func (b *box) tun(t cloudwire.Tun) {
	body, _ := cloudwire.Marshal(t)
	raw, _ := cloudwire.Envelope{T: cloudwire.MsgTun, B: body}.Encode()
	frame, _ := cloudwire.EncodeFrame(raw)
	_ = b.conn.WriteMessage(websocket.BinaryMessage, frame)
}

// tun from the box is not held to its message rate, and a tun for a phone
// that is not there ends the box's session at once.
func TestATunForNoPhoneIsEndedAndTunIsNotTheBoxsRate(t *testing.T) {
	s := newService(t)
	b := tunConnect(t, s)
	wait(t, "the roster", func() bool {
		_, err := s.store.For(store.Principal{Kind: store.Device, Home: b.home, DeviceKey: ownerKey})
		return err == nil
	})
	for i := range rateBurst + 20 {
		b.tun(cloudwire.Tun{Dev: "owner", Sid: uint32(i), D: []byte{1}})
	}
	ends := 0
	for ends < rateBurst+20 {
		env := b.read()
		var t2 cloudwire.Tun
		if env.T != cloudwire.MsgTun || cloudwire.Unmarshal(env.B, &t2) != nil || !t2.Ended() {
			t.Fatalf("got %q %+v", env.T, t2)
		}
		ends++
	}
}

// Past a home's tun limits the service drops and counts, and the box stays
// connected.
func TestPastTheTunLimitsTheServiceDrops(t *testing.T) {
	s := newService(t)
	b := tunConnect(t, s)
	wait(t, "the box is the home's", func() bool { return s.up.Tun(b.home, cloudwire.Tun{Dev: "owner", Sid: 1}) })
	big := make([]byte, cloudwire.TunDataMax)
	for range 300 {
		s.up.Tun(b.home, cloudwire.Tun{Dev: "owner", Sid: 1, D: big})
	}
	if s.up.TunDropped.Load() == 0 {
		t.Fatal("nothing was dropped past 4 MiB in a burst")
	}
	if !s.up.Tun(b.home, cloudwire.Tun{Dev: "owner", Sid: 1}) {
		t.Fatal("the box is gone")
	}
}

// A box that sends tun at twice the home's limits is not pacing its tunnel,
// and its uplink closes.
func TestABoxFloodingTunIsClosed(t *testing.T) {
	s := newService(t)
	b := tunConnect(t, s)
	for range 3 * tunMsgBurst {
		b.tun(cloudwire.Tun{Dev: "nobody", Sid: 1})
	}
	if !b.closed() {
		t.Fatal("a box flooding tun stayed connected")
	}
}
