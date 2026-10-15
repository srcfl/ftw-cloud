package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

var newKey = bytes.Repeat([]byte{0x31}, 32)

func tunRoster(seq uint64, serve bool, pending ...[]byte) *cloudwire.Roster {
	r := &cloudwire.Roster{RosterSeq: seq, TTLS: 86_400,
		Devices: []cloudwire.Device{
			{ID: "owner", Key: ownerKey, Role: "owner", Scopes: protocol.CloudScopes, Tun: true},
			{ID: "watch", Key: viewerKey, Role: "watch", Scopes: []string{protocol.ScopeLiveRead}},
		},
		Grant: cloudwire.Grant{Controller: "sourceful"}}
	if serve {
		r.Grant = cloudwire.Grant{ID: make([]byte, 16), Scopes: []string{protocol.ScopeLiveRead},
			Purposes: []string{protocol.CloudPurposeServe}, Controller: "sourceful"}
	}
	for _, h := range pending {
		r.Pending = append(r.Pending, cloudwire.Pending{Hash: h, TTLS: 600})
	}
	return r
}

func tunHome(t *testing.T, r *cloudwire.Roster) (*Store, *Handle, *clock) {
	t.Helper()
	c := &clock{t: time.Unix(1_791_820_800, 0)}
	s := New(c.now)
	box, err := s.For(Principal{Kind: Box, Home: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	box.Connected()
	box.SetRoster(r)
	return s, box, c
}

// A box that connects again ends the tunnels its older uplink carried, even
// while the old socket is still open.
func TestANewUplinkEndsTheOldOnesTunnels(t *testing.T) {
	s, box, _ := tunHome(t, tunRoster(1, false))
	dev, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if err != nil {
		t.Fatal(err)
	}
	_, sess, err := dev.Open()
	if err != nil {
		t.Fatal(err)
	}
	sess.SetSid(7)
	box.Connected()
	select {
	case m := <-sess.Tun():
		if m.Sid != 7 || len(m.D) != 0 {
			t.Fatalf("the phone heard %+v", m)
		}
	default:
		t.Fatal("the phone's tunnel outlived its uplink")
	}
}

// Readings go when a roster stops serving, however the copy ended.
func TestReadingsGoWhenTheRosterStopsServing(t *testing.T) {
	s, box, _ := tunHome(t, tunRoster(1, true))
	_ = box.Put(cloudwire.MsgLive, []byte("live"), 2, true)
	box.SetRoster(tunRoster(2, false))
	box.SetRoster(tunRoster(3, true))
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if snap, _ := dev.Snapshot(); len(snap.Envelopes) != 0 {
		t.Fatalf("%d readings outlived a roster that did not serve", len(snap.Envelopes))
	}
}

// A pairing hash admits only a key the roster does not list, is spent only
// when the session opens, and does not come back with a restart.
func TestAPairingHashIsForANewKeyOnce(t *testing.T) {
	hash := bytes.Repeat([]byte{0x77}, cloudwire.PairingHashBytes)
	s, _, c := tunHome(t, tunRoster(1, false, hash))
	// The watch is listed, may not tunnel and the copy is off: refused, and
	// the hash does not let it in either.
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: viewerKey, Pair: hash}); !errors.Is(err, ErrDenied) {
		t.Fatalf("a listed key came in by pairing: %v", err)
	}
	// A busy home spends nothing.
	h := s.homes["h1"]
	for range MaxSessionsPerHome {
		h.sessions[&Session{x: &Handle{device: cloudwire.Device{Key: bytes.Repeat([]byte{9}, 32)}}}] = struct{}{}
	}
	x, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: newKey, Pair: hash})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.Open(); !errors.Is(err, ErrBusy) {
		t.Fatalf("a full home: %v", err)
	}
	h.sessions = map[*Session]struct{}{}
	if _, _, err := x.Open(); err != nil {
		t.Fatalf("the hash was spent by a busy home: %v", err)
	}
	other := bytes.Repeat([]byte{0x32}, 32)
	y, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: other, Pair: hash})
	if err == nil {
		if _, _, err := y.Open(); err == nil {
			t.Fatal("a pairing hash opened two sessions")
		}
	}

	// A restart seeds the roster without its pairing codes.
	fresh := New(c.now)
	fresh.Seed("h1", tunRoster(1, false, hash), c.now())
	if _, err := fresh.For(Principal{Kind: Device, Home: "h1", DeviceKey: other, Pair: hash}); err == nil {
		t.Fatal("a restart brought a pairing code back")
	}
}

// A roster that takes a device's tunnel away ends its session.
func TestLosingTunEndsTheSession(t *testing.T) {
	s, box, _ := tunHome(t, tunRoster(1, true))
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	_, sess, err := dev.Open()
	if err != nil {
		t.Fatal(err)
	}
	r := tunRoster(2, true)
	r.Devices[0].Tun = false
	box.SetRoster(r)
	select {
	case <-sess.Done():
		if sess.Code() != cloudwire.CloseChanged {
			t.Fatalf("closed with %d", sess.Code())
		}
	default:
		t.Fatal("the session kept a tunnel the roster took away")
	}
}
