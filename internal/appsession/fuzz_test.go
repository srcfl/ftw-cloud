package appsession

import (
	"bytes"
	"testing"

	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Whatever a phone sends after the handshake, the service neither panics nor
// does more than the protocol allows: a phone can change whether it looks,
// and an owner can suspend a device in the roster. Nothing else changes.
func FuzzPhoneMessage(f *testing.F) {
	h := newHarness(f)
	h.live(true)
	for _, seed := range [][]byte{
		mustFrame(cloudwire.MsgWatch, cloudwire.Watch{Hz: 1}),
		mustFrame(cloudwire.MsgWatch, cloudwire.Watch{Hz: 0}),
		mustFrame(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"}),
		mustFrame(cloudwire.MsgUnsuspend, cloudwire.Suspend{DeviceID: "viewer"}),
		mustFrame("token.get", struct{}{}),
		{1, 1, 0, 0, 0, 1, 0xa0},
		{1, 0, 0, 0, 0, 0},
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		for _, key := range []appwire.KeyPair{h.viewer, h.owner} {
			dev, err := h.store.For(storePrincipal(h, key))
			if err != nil {
				t.Fatal(err)
			}
			c := &phoneConn{s: h.app, dev: dev, home: h.home, tokens: rateBurst, refilled: h.app.now()}
			code, err := c.apply(frame)
			if err != nil && code != cloudwire.CloseProtocol && code != 0 {
				t.Fatalf("closed with %d", code)
			}
			c.stopLooking()
			// Only the owner may suspend, and only the viewer exists to be
			// suspended besides the owner itself.
			if bytes.Equal(key.Public(), h.viewer.Public()) && h.reg.Suspended(h.home, "owner", 1) {
				t.Fatal("a viewer suspended the owner")
			}
			_ = h.reg.Unsuspend(h.home, "viewer")
			_ = h.reg.Unsuspend(h.home, "owner")
		}
		h.app.mu.Lock()
		left := len(h.app.looking)
		h.app.mu.Unlock()
		if left != 0 {
			t.Fatal("a session that ended is still counted as looking")
		}
	})
}

// Message 1's payload: anything at all is refused or read, never a panic.
func FuzzNow(f *testing.F) {
	now, _ := cloudwire.Unsigned(cloudwire.MsgNow, cloudwire.Now{Hz: 1})
	f.Add(now)
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = parseNow(payload)
	})
}

func mustFrame(t string, body any) []byte {
	env, err := cloudwire.Unsigned(t, body)
	if err != nil {
		panic(err)
	}
	frame, err := cloudwire.EncodeFrame(env)
	if err != nil {
		panic(err)
	}
	return frame
}

// Whatever message 1 of a one-shot read carries, the service neither panics
// nor does more than the protocol allows: it answers or refuses with a
// status the protocol names, a viewer suspends nobody, and nothing stays
// counted after the answer.
func FuzzOnceMessage(f *testing.F) {
	h := newHarness(f)
	h.live(true)
	for _, seed := range []struct {
		t    string
		body any
	}{
		{cloudwire.MsgRead, cloudwire.Read{Hz: 1}},
		{cloudwire.MsgRead, cloudwire.Read{Have: cloudwire.Have{Boot: h.boot, Seq: map[string]uint64{"live": 9}}}},
		{cloudwire.MsgTokenGet, struct{}{}},
		{cloudwire.MsgPushRegister, cloudwire.PushRegister{APNsToken: []byte{1}, Environment: "sandbox", Kind: "alert", App: "watch"}},
		{cloudwire.MsgPushUnregister, cloudwire.PushUnregister{APNsToken: []byte{1}}},
		{cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "owner"}},
	} {
		payload, _ := cloudwire.Unsigned(seed.t, seed.body)
		f.Add(payload)
	}
	f.Add([]byte{0xa0})
	f.Add([]byte{})
	allowed := map[int]bool{200: true, 400: true, 403: true, 429: true, 501: true}
	f.Fuzz(func(t *testing.T, payload []byte) {
		h.app.once = onceLimits{homes: map[string]int{}, devices: map[string]*onceDevice{}}
		init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: h.viewer, RemoteStatic: h.noise.Public(),
			Prologue: cloudwire.OncePrologue(h.home)})
		if err != nil {
			t.Fatal(err)
		}
		msg1, err := init.WriteMessage(payload)
		if err != nil {
			return // larger than one Noise message: never reaches the service
		}
		body, status := h.app.answerOnce(h.home, msg1)
		if !allowed[status] {
			t.Fatalf("status %d", status)
		}
		if status == 200 {
			if _, err := cloudwire.SplitOnceAnswer(body); err != nil {
				t.Fatal(err)
			}
		}
		if h.reg.Suspended(h.home, "owner", 1) {
			t.Fatal("a viewer's one-shot read suspended the owner")
		}
		if open, _ := h.app.once.held(); open != 0 {
			t.Fatal("a read is still counted after its answer")
		}
	})
}
