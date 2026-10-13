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
