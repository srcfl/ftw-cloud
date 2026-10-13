package appsession

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// countedPush is the push service, counting the calls the sessions make.
type countedPush struct {
	*push.Service
	calls atomic.Int32
}

func (p *countedPush) Register(home string, dev cloudwire.Device, scopes []string, r cloudwire.PushRegister) error {
	defer p.calls.Add(1)
	return p.Service.Register(home, dev, scopes, r)
}

func (p *countedPush) Unregister(home string, dev cloudwire.Device, r cloudwire.PushUnregister) error {
	defer p.calls.Add(1)
	return p.Service.Unregister(home, dev, r)
}

// A phone registers its APNs token over its own session. The roster entry
// and scope come from the session, never from the message: a viewer's
// registration registers nothing and its session goes on.
func TestAPhoneRegistersItsTokenOverItsSession(t *testing.T) {
	h := newHarness(t)
	h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead, protocol.ScopeEventsRead)
	p := &countedPush{Service: push.New(h.reg, nil, nil)}
	h.app.Push = p
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	viewer := h.mustDial(dialOpts{key: h.viewer})
	register := func(token byte) cloudwire.PushRegister {
		return cloudwire.PushRegister{APNsToken: bytes.Repeat([]byte{token}, 32),
			Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert}
	}
	regs := func() []string {
		got, err := h.reg.PushRegs(h.home, cloudwire.PushKindAlert)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range got {
			out = append(out, r.DeviceID)
		}
		return out
	}

	viewer.send(cloudwire.MsgPushRegister, register(0xa1))
	owner.send(cloudwire.MsgPushRegister, register(0xa2))
	waitFor(t, "both registrations", func() bool { return p.calls.Load() == 2 })
	if got := regs(); len(got) != 1 || got[0] != "owner" {
		t.Fatalf("registered %v, want the owner alone", got)
	}
	next := h.live(false)
	for name, ph := range map[string]*phone{"viewer": viewer, "owner": owner} {
		if got, code := ph.next(time.Second); code != 0 || !bytes.Equal(got, next) {
			t.Fatalf("the %s's session did not go on: code %d", name, code)
		}
	}

	owner.send(cloudwire.MsgPushUnregister, cloudwire.PushUnregister{APNsToken: register(0xa2).APNsToken})
	waitFor(t, "the unregistration", func() bool { return p.calls.Load() == 3 })
	if got := regs(); len(got) != 0 {
		t.Fatalf("still registered: %v", got)
	}

	// A registration the service cannot read is a protocol error.
	owner.send(cloudwire.MsgPushRegister, "not a registration")
	if code := owner.closed(2 * time.Second); code != cloudwire.CloseProtocol {
		t.Fatalf("an unreadable registration closed with %d", code)
	}
}

// Without a push service, a registration is ignored and the session goes on.
func TestWithoutPushARegistrationIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	owner.send(cloudwire.MsgPushRegister, cloudwire.PushRegister{APNsToken: []byte{1},
		Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert})
	next := h.live(false)
	if got, code := owner.next(time.Second); code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("the session did not go on: code %d", code)
	}
}
