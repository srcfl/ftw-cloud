package store

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

var (
	ownerKey  = bytes.Repeat([]byte{1}, 32)
	viewerKey = bytes.Repeat([]byte{2}, 32)
)

func roster(seq uint64, grant ...string) *cloudwire.Roster {
	return &cloudwire.Roster{RosterSeq: seq, TTLS: 86_400,
		Devices: []cloudwire.Device{
			{ID: "owner", Key: ownerKey, Role: "owner", Scopes: protocol.CloudScopes},
			{ID: "viewer", Key: viewerKey, Role: "viewer", Scopes: []string{protocol.ScopeLiveRead}},
		},
		Grant: cloudwire.Grant{ID: make([]byte, 16), Scopes: grant, Controller: "sourceful"}}
}

func filled(t *testing.T) (*Store, *Handle, *clock) {
	c := &clock{t: time.Unix(1_791_820_800, 0)}
	s := New(c.now)
	box, err := s.For(Principal{Kind: Box, Home: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	box.Connected()
	box.SetRoster(roster(1, protocol.ScopeLiveRead, protocol.ScopePlanRead))
	_ = box.Put(cloudwire.MsgLive, []byte("live-full"), 3, true)
	_ = box.Put(cloudwire.MsgPlan, []byte("plan"), 4, false)
	_ = box.Put(cloudwire.MsgLive, []byte("live-delta"), 5, false)
	_ = box.Put(cloudwire.MsgHB, []byte("hb"), 6, false)
	_ = box.Put(cloudwire.MsgEvent, []byte("event"), 7, false)
	return s, box, c
}

func TestOnlyThePrincipalsOwnHome(t *testing.T) {
	s, _, _ := filled(t)
	for name, p := range map[string]Principal{
		"no kind":           {Home: "h1"},
		"unknown home":      {Kind: Device, Home: "h2", DeviceKey: ownerKey},
		"key not in roster": {Kind: Device, Home: "h1", DeviceKey: bytes.Repeat([]byte{9}, 32)},
		"empty key":         {Kind: Device, Home: "h1"},
		"empty home":        {Kind: Box},
	} {
		if _, err := s.For(p); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A device reads its effective scope: its role's scopes within the grant.
// The owner reads plan here because the grant has it; nobody reads event,
// which the grant lacks.
func TestADeviceReadsOnlyItsEffectiveScope(t *testing.T) {
	s, _, _ := filled(t)
	read := func(key []byte) []string {
		x, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: key})
		if err != nil {
			t.Fatal(err)
		}
		snap, err := x.Snapshot()
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, e := range snap.Envelopes {
			got = append(got, string(e))
		}
		return got
	}
	if got := read(ownerKey); len(got) != 4 || got[0] != "live-full" || got[1] != "plan" || got[2] != "live-delta" || got[3] != "hb" {
		t.Fatalf("owner read %v", got)
	}
	if got := read(viewerKey); len(got) != 3 || got[0] != "live-full" || got[2] != "hb" {
		t.Fatalf("viewer read %v", got)
	}
}

func TestABoxCannotReadAndADeviceCannotWrite(t *testing.T) {
	s, box, _ := filled(t)
	if _, err := box.Snapshot(); !errors.Is(err, ErrDenied) {
		t.Fatal("the box's handle read the home")
	}
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if err := dev.Put(cloudwire.MsgLive, []byte("forged"), 99, true); !errors.Is(err, ErrDenied) {
		t.Fatal("a device wrote the home")
	}
	if dev.SetRoster(roster(9)) {
		t.Fatal("a device set the roster")
	}
}

func TestAnExpiredRosterLocksDevicesOut(t *testing.T) {
	s, _, c := filled(t)
	c.t = c.t.Add(24*time.Hour + time.Second)
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey}); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired roster: %v", err)
	}
}

func TestAnOlderRosterIsIgnoredAndAnEqualOneRenews(t *testing.T) {
	s, box, c := filled(t)
	if box.SetRoster(roster(0)) {
		t.Fatal("an older roster replaced a newer one")
	}
	c.t = c.t.Add(20 * time.Hour)
	if !box.SetRoster(roster(1, protocol.ScopeLiveRead)) {
		t.Fatal("an equal roster was refused")
	}
	c.t = c.t.Add(20 * time.Hour)
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey}); err != nil {
		t.Fatal("an equal roster did not renew its time to live")
	}
}

// An hour after the box went quiet a phone gets when it was last seen, and
// no readings.
func TestReadingsGoAnHourAfterTheBox(t *testing.T) {
	s, box, c := filled(t)
	gen := box.Connected()
	box.Disconnected(gen)
	c.t = c.t.Add(ReadingsKeptFor + time.Second)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	snap, _ := dev.Snapshot()
	if len(snap.Envelopes) != 0 || snap.Online || snap.LastSeenMs == 0 {
		t.Fatalf("after an hour: %+v", snap)
	}
	s.Sweep()
	c.t = c.t.Add(-time.Hour) // even read back early, the sweep dropped them
	snap, _ = dev.Snapshot()
	if len(snap.Envelopes) != 0 {
		t.Fatal("the sweep left readings in memory")
	}
}

func TestANewerConnectionOutlivesAnOlderOne(t *testing.T) {
	s, box, c := filled(t)
	first := box.Connected()
	second := box.Connected()
	box.Disconnected(first)
	c.t = c.t.Add(2 * ReadingsKeptFor)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if snap, _ := dev.Snapshot(); !snap.Online || len(snap.Envelopes) == 0 {
		t.Fatalf("the old connection's close took the home offline: %+v", snap)
	}
	box.Disconnected(second)
}

func TestDeleteForgetsTheHome(t *testing.T) {
	s, box, _ := filled(t)
	box.Delete()
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey}); !errors.Is(err, ErrDenied) {
		t.Fatal("a deleted home still answers")
	}
}

// A session's snapshot and stream join without a gap: what the box sends
// after Open reaches the session, and nothing before it does twice.
func TestASessionMissesNothingAfterItsSnapshot(t *testing.T) {
	s, box, _ := filled(t)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: viewerKey})
	snap, sess, err := dev.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if len(snap.Envelopes) != 3 {
		t.Fatalf("snapshot held %d", len(snap.Envelopes))
	}
	_ = box.Put(cloudwire.MsgPlan, []byte("plan-2"), 8, false) // outside the viewer's scope
	_ = box.Put(cloudwire.MsgLive, []byte("live-3"), 9, false)
	select {
	case got := <-sess.C():
		if string(got) != "live-3" {
			t.Fatalf("the session got %q", got)
		}
	default:
		t.Fatal("nothing reached the session")
	}
	select {
	case got := <-sess.C():
		t.Fatalf("the session also got %q", got)
	default:
	}
}

// A phone too far behind is ended, never allowed to stall the box.
func TestASlowSessionIsEndedNotWaitedFor(t *testing.T) {
	s, box, _ := filled(t)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	_, sess, _ := dev.Open()
	for i := range SessionQueue + 1 {
		_ = box.Put(cloudwire.MsgHB, []byte("hb"), uint64(100+i), false)
	}
	select {
	case <-sess.Done():
	default:
		t.Fatal("a full queue left the session open")
	}
	if sess.Code() != closeSlow {
		t.Fatalf("ended with %d", sess.Code())
	}
}

func TestARosterThatRunsOutEndsSessions(t *testing.T) {
	s, _, c := filled(t)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	_, sess, _ := dev.Open()
	c.t = c.t.Add(24*time.Hour + time.Second)
	s.Sweep()
	select {
	case <-sess.Done():
	default:
		t.Fatal("an expired roster left a session open")
	}
	if sess.Code() != cloudwire.CloseDenied {
		t.Fatalf("ended with %d", sess.Code())
	}
}

func TestForgettingAHomeEndsItsSessions(t *testing.T) {
	s, _, _ := filled(t)
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	_, sess, _ := dev.Open()
	s.Forget("h1")
	select {
	case <-sess.Done():
	default:
		t.Fatal("a forgotten home kept a session")
	}
}

// A suspended device is refused, and only at the epoch it was suspended at.
func TestSuspensionsAreConsultedOnEveryAdmission(t *testing.T) {
	s, _, _ := filled(t)
	s.UseSuspensions(func(home, id string, epoch uint64) bool { return home == "h1" && id == "viewer" && epoch == 0 })
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: viewerKey}); !errors.Is(err, ErrDenied) {
		t.Fatal("a suspended device was admitted")
	}
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey}); err != nil {
		t.Fatal("the owner was refused with the viewer")
	}
}

func TestABoxHandleCannotOpenASession(t *testing.T) {
	_, box, _ := filled(t)
	if _, _, err := box.Open(); !errors.Is(err, ErrDenied) {
		t.Fatal("the box's handle opened a session")
	}
}

// A token reaches its home through the roster entry it is bound to, at that
// epoch, and reads only Now: the newest live, prices and hb, and the newest
// live that carried sources.
func TestATokenReadsOnlyNow(t *testing.T) {
	s, box, _ := filled(t)
	_ = box.Put(cloudwire.MsgPrices, []byte("prices"), 8, false)
	_ = box.Put(cloudwire.MsgLP, []byte("lp"), 9, false)
	_ = box.Put(cloudwire.MsgHealth, []byte("health"), 10, false)
	_ = box.Put(cloudwire.MsgTiles, []byte("tiles"), 11, false)
	box.SetRoster(roster(2, protocol.CloudScopes...))
	x, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := x.Now()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range snap.Envelopes {
		got = append(got, string(e))
	}
	if want := []string{"live-full", "live-delta", "hb", "prices"}; !slices.Equal(got, want) {
		t.Fatalf("a token read %v, want %v", got, want)
	}
	if _, err := x.Snapshot(); !errors.Is(err, ErrDenied) {
		t.Fatal("a token read the whole snapshot")
	}
	if _, _, err := x.Open(); !errors.Is(err, ErrDenied) {
		t.Fatal("a token opened a session")
	}
	dev, _ := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if _, err := dev.Now(); !errors.Is(err, ErrDenied) {
		t.Fatal("a device key read Now as a token")
	}
}

// A token is held to the same rule as a device: a roster in force that lists
// its entry at its epoch, and no suspension.
func TestATokenIsAdmittedAsItsDeviceIs(t *testing.T) {
	s, box, c := filled(t)
	for name, p := range map[string]Principal{
		"no device":      {Kind: Token, Home: "h1"},
		"another device": {Kind: Token, Home: "h1", DeviceID: "stranger"},
		"another epoch":  {Kind: Token, Home: "h1", DeviceID: "owner", Epoch: 1},
		"another home":   {Kind: Token, Home: "h2", DeviceID: "owner"},
	} {
		if _, err := s.For(p); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s.UseSuspensions(func(home, id string, epoch uint64) bool { return id == "viewer" })
	if _, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "viewer"}); !errors.Is(err, ErrDenied) {
		t.Fatal("a suspended device's token was admitted")
	}
	c.t = c.t.Add(24*time.Hour + time.Second)
	if _, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "owner"}); !errors.Is(err, ErrDenied) {
		t.Fatal("a token read past an expired roster")
	}
	box.SetRoster(roster(2, protocol.ScopeLiveRead))
	if _, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "owner"}); err != nil {
		t.Fatal("a renewed roster still refused the token")
	}
	box.Delete()
	if _, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "owner"}); !errors.Is(err, ErrDenied) {
		t.Fatal("a token reached a deleted home")
	}
}

// A token whose device may not read live gets the hb alone.
func TestATokenReadsWithinItsDevicesScope(t *testing.T) {
	s, box, _ := filled(t)
	_ = box.Put(cloudwire.MsgPrices, []byte("prices"), 8, false)
	box.SetRoster(roster(2, protocol.ScopePlanRead))
	x, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := x.Now()
	if len(snap.Envelopes) != 1 || string(snap.Envelopes[0]) != "hb" {
		t.Fatalf("a token without live read %q", snap.Envelopes)
	}
}
