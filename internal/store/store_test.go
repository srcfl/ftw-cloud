package store

import (
	"bytes"
	"errors"
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
