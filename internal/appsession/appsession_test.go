package appsession

import (
	"bytes"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The snapshot carries the box's own bytes in rising seq, and every later
// envelope follows on the same connection, unchanged.
func TestSnapshotThenStreamCarryTheBoxsBytes(t *testing.T) {
	h := newHarness(t)
	full := h.live(true)
	plan := h.plan()
	delta := h.live(false)
	hb := h.hb()

	p := h.mustDial(dialOpts{key: h.owner, hz: 1})
	want := [][]byte{full, plan, delta, hb}
	if len(p.snap.Envelopes) != len(want) || !p.snap.Online || p.snap.More != 0 {
		t.Fatalf("snapshot: %d envelopes, online %v, more %d", len(p.snap.Envelopes), p.snap.Online, p.snap.More)
	}
	pub := &h.boxKey.PublicKey
	for i, e := range p.snap.Envelopes {
		if !bytes.Equal(e, want[i]) {
			t.Fatalf("snapshot entry %d is not the box's bytes", i)
		}
		verify(t, pub, h.home, e)
	}

	next := h.live(false)
	got, code := p.next(2 * time.Second)
	if code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("the stream carried %x (code %d), not the box's envelope", got, code)
	}
	verify(t, pub, h.home, got)
}

func verify(t *testing.T, pub *ecdsa.PublicKey, home string, raw []byte) {
	t.Helper()
	env, err := cloudwire.DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := cloudwire.Verify(pub, home, env); err != nil {
		t.Fatalf("%s does not verify with the box key: %v", env.T, err)
	}
}

// A viewer reads its effective scope, on the snapshot and on the stream.
func TestAViewerReadsOnlyItsScope(t *testing.T) {
	h := newHarness(t)
	full := h.live(true)
	h.plan()
	p := h.mustDial(dialOpts{key: h.viewer, hz: 1})
	if len(p.snap.Envelopes) != 1 || !bytes.Equal(p.snap.Envelopes[0], full) {
		t.Fatalf("viewer snapshot: %d envelopes", len(p.snap.Envelopes))
	}
	h.plan()
	hb := h.hb()
	got, _ := p.next(2 * time.Second)
	if !bytes.Equal(got, hb) {
		t.Fatal("the viewer was sent a plan, or not the hb")
	}
}

// Every refusal closes before message 2 with the one code that says nothing
// about which check failed.
func TestRefusalsSayNothing(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	stranger, _ := appwire.GenerateKeyPair()
	otherService, _ := appwire.GenerateKeyPair()
	otherHome := "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	for name, o := range map[string]dialOpts{
		"a key the roster lacks":   {key: stranger},
		"another service key":      {key: h.owner, service: otherService.Public()},
		"another home in prologue": {key: h.owner, prologue: otherHome},
		"a home the service lacks": {key: h.owner, home: otherHome},
	} {
		_, code, err := h.dial(o)
		if err != nil || code != cloudwire.CloseDenied {
			t.Errorf("%s: code %d, %v", name, code, err)
		}
	}
}

// The doc's C3 proof: a revoke cuts the stream within a second.
func TestARosterWithoutTheDeviceClosesItsSessionWithinASecond(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	viewer := h.mustDial(dialOpts{key: h.viewer, hz: 1})
	owner := h.mustDial(dialOpts{key: h.owner, hz: 1})

	start := time.Now()
	h.setRoster(h.devices(1, 1)[:1], protocol.ScopeLiveRead, protocol.ScopePlanRead)
	if code := viewer.closed(time.Second); code != cloudwire.CloseDenied {
		t.Fatalf("revoked viewer closed with %d", code)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("revoke took %v", took)
	}
	// The owner's access did not change, so its stream goes on.
	next := h.live(false)
	if got, code := owner.next(time.Second); code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("the owner's stream ended with the viewer's: code %d", code)
	}
	if _, code, _ := h.dial(dialOpts{key: h.viewer}); code != cloudwire.CloseDenied {
		t.Fatalf("a revoked device reconnected: code %d", code)
	}
}

// Narrower scopes or a new epoch end the session; the phone comes back and
// learns what it may read now.
func TestAChangedAccessEndsTheSession(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead) // plan dropped from the grant
	if code := owner.closed(time.Second); code != cloudwire.CloseChanged {
		t.Fatalf("narrowed grant closed with %d", code)
	}
	viewer := h.mustDial(dialOpts{key: h.viewer})
	h.setRoster(h.devices(1, 2), protocol.ScopeLiveRead) // viewer paired again
	if code := viewer.closed(time.Second); code != cloudwire.CloseChanged {
		t.Fatalf("new epoch closed with %d", code)
	}
	h.mustDial(dialOpts{key: h.viewer})
}

func TestTurningFTWCloudOffClosesEverySession(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	p := h.mustDial(dialOpts{key: h.owner})
	h.box.Delete()
	if code := p.closed(time.Second); code != cloudwire.CloseDenied {
		t.Fatalf("purge closed with %d", code)
	}
}

// An owner's suspension only narrows: it closes the device's session and
// keeps it out, a viewer cannot suspend anyone, a device outside the roster
// cannot be named, and lifting it gives back what the roster allows.
func TestSuspensionOnlyNarrows(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	viewer := h.mustDial(dialOpts{key: h.viewer})

	viewer.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "owner"})
	owner.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "nobody"})
	next := h.live(false)
	if got, code := owner.next(time.Second); code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("a viewer suspended the owner: code %d", code)
	}
	if h.reg.Suspended(h.home, "nobody", 0) {
		t.Fatal("a device outside the roster was suspended")
	}

	owner.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"})
	if code := viewer.closed(time.Second); code != cloudwire.CloseDenied {
		t.Fatalf("suspended viewer closed with %d", code)
	}
	if _, code, _ := h.dial(dialOpts{key: h.viewer}); code != cloudwire.CloseDenied {
		t.Fatalf("a suspended device reconnected: code %d", code)
	}

	owner.send(cloudwire.MsgUnsuspend, cloudwire.Suspend{DeviceID: "viewer"})
	waitFor(t, "the suspension to lift", func() bool { return !h.reg.Suspended(h.home, "viewer", 1) })
	h.mustDial(dialOpts{key: h.viewer})

	// Paired again on the box: a new epoch ends a suspension.
	owner.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"})
	waitFor(t, "the suspension", func() bool { return h.reg.Suspended(h.home, "viewer", 1) })
	h.setRoster(h.devices(1, 2), protocol.ScopeLiveRead, protocol.ScopePlanRead)
	h.mustDial(dialOpts{key: h.viewer})
}

// While a phone looks, the box is asked for one-second updates, and asked
// again before its watch lapses. When nobody looks, the asking stops.
func TestTheBoxIsWatchedWhileAPhoneLooks(t *testing.T) {
	h := newHarness(t)
	h.app.renewEvery = 40 * time.Millisecond
	h.live(true)

	away := h.mustDial(dialOpts{key: h.viewer, hz: 0})
	time.Sleep(60 * time.Millisecond)
	if n := h.watch.count(); n != 0 {
		t.Fatalf("a phone that is not looking caused %d watches", n)
	}
	looking := h.mustDial(dialOpts{key: h.owner, hz: 1})
	waitFor(t, "renewals", func() bool { return h.watch.count() >= 3 })

	// Two phones looking, one looks away: still watched.
	away.send(cloudwire.MsgWatch, cloudwire.Watch{Hz: 1})
	looking.send(cloudwire.MsgWatch, cloudwire.Watch{Hz: 0})
	n := h.watch.count()
	waitFor(t, "renewals with one phone left", func() bool { return h.watch.count() >= n+2 })

	away.send(cloudwire.MsgWatch, cloudwire.Watch{Hz: 0})
	waitFor(t, "the watch to stop", func() bool {
		h.app.mu.Lock()
		defer h.app.mu.Unlock()
		return len(h.app.looking) == 0
	})
	n = h.watch.count()
	time.Sleep(120 * time.Millisecond)
	if h.watch.count() != n {
		t.Fatal("the service kept asking with nobody looking")
	}

	// A closed session stops its share too.
	away.send(cloudwire.MsgWatch, cloudwire.Watch{Hz: 1})
	waitFor(t, "a watch", func() bool { return h.watch.count() > n })
	away.conn.Close()
	waitFor(t, "the watch to stop after close", func() bool {
		h.app.mu.Lock()
		defer h.app.mu.Unlock()
		return len(h.app.looking) == 0
	})
}

func TestABoxThatComesBackIsAskedAtOnce(t *testing.T) {
	h := newHarness(t)
	h.app.renewEvery = time.Hour
	h.live(true)
	h.mustDial(dialOpts{key: h.owner, hz: 1})
	waitFor(t, "the first watch", func() bool { return h.watch.count() == 1 })
	h.app.BoxConnected(h.home)
	h.app.BoxConnected("aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if n := h.watch.count(); n != 2 {
		t.Fatalf("watches after the box came back: %d", n)
	}
}

func TestANewSessionFromTheSameDeviceReplacesTheOld(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	first := h.mustDial(dialOpts{key: h.owner})
	h.mustDial(dialOpts{key: h.owner})
	if code := first.closed(time.Second); code != cloudwire.CloseReplaced {
		t.Fatalf("the older session closed with %d", code)
	}
}

func TestAHomeHoldsABoundedNumberOfSessions(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	var devices []cloudwire.Device
	var keys []appwire.KeyPair
	for i := 0; i <= store.MaxSessionsPerHome; i++ {
		k, _ := appwire.GenerateKeyPair()
		keys = append(keys, k)
		devices = append(devices, cloudwire.Device{ID: string(rune('a' + i)), Key: k.Public(), Role: "viewer",
			Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1})
	}
	h.setRoster(devices, protocol.ScopeLiveRead)
	for _, k := range keys[:store.MaxSessionsPerHome] {
		h.mustDial(dialOpts{key: k})
	}
	if _, code, _ := h.dial(dialOpts{key: keys[store.MaxSessionsPerHome]}); code != cloudwire.CloseBusy {
		t.Fatalf("one session over the limit: code %d", code)
	}
}

// A snapshot larger than one Noise message spills its newest envelopes into
// frames right after message 2, still in rising seq.
func TestALargeSnapshotSpillsIntoFrames(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	big := func(class string) []byte {
		return h.put(class, func(hdr cloudwire.Header) any {
			return struct {
				cloudwire.Header
				Pad []byte `cbor:"pad"`
			}{hdr, bytes.Repeat([]byte{7}, 30_000)}
		}, false)
	}
	plan := big(cloudwire.MsgPlan)
	prices := big(cloudwire.MsgPrices)
	lp := big(cloudwire.MsgLP)
	p := h.mustDial(dialOpts{key: h.owner})
	if p.snap.More == 0 || len(p.snap.Envelopes)+p.snap.More != 4 {
		t.Fatalf("snapshot held %d, more %d", len(p.snap.Envelopes), p.snap.More)
	}
	var rest [][]byte
	for range p.snap.More {
		env, code := p.next(time.Second)
		if code != 0 {
			t.Fatalf("closed with %d", code)
		}
		rest = append(rest, env)
	}
	var all [][]byte
	for _, e := range p.snap.Envelopes {
		all = append(all, e)
	}
	all = append(all, rest...)
	for i, want := range [][]byte{plan, prices, lp} {
		if !bytes.Equal(all[i+1], want) {
			t.Fatalf("entry %d out of order", i+1)
		}
	}
}

func TestAPhoneThatFloodsIsClosed(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	p := h.mustDial(dialOpts{key: h.owner})
	for range rateBurst + 5 {
		env, _ := cloudwire.Unsigned("chatter", struct{}{})
		frame, _ := cloudwire.EncodeFrame(env)
		msg, _ := p.tr.Encrypt(frame)
		if p.conn.WriteMessage(websocket.BinaryMessage, msg) != nil {
			break
		}
	}
	if code := p.closed(2 * time.Second); code != cloudwire.CloseProtocol {
		t.Fatalf("a flood closed with %d", code)
	}
}

func TestATamperedMessageClosesTheSession(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	p := h.mustDial(dialOpts{key: h.owner})
	env, _ := cloudwire.Unsigned(cloudwire.MsgWatch, cloudwire.Watch{Hz: 0})
	frame, _ := cloudwire.EncodeFrame(env)
	msg, _ := p.tr.Encrypt(frame)
	msg[len(msg)-1] ^= 1
	_ = p.conn.WriteMessage(websocket.BinaryMessage, msg)
	if code := p.closed(2 * time.Second); code != cloudwire.CloseProtocol {
		t.Fatalf("a tampered message closed with %d", code)
	}
}

func TestPlainHTTPAndABadHomeAreRefused(t *testing.T) {
	h := newHarness(t)
	resp, err := h.srv.Client().Get(h.srv.URL + "/v1/app?home=nothome")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("a bad home: %d", resp.StatusCode)
	}
}
