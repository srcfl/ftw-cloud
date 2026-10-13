package push

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type fakeApple struct {
	mu   sync.Mutex
	sent []apns.Notification
	gone map[string]bool
}

func (f *fakeApple) Send(_ context.Context, n apns.Notification) (apns.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, n)
	if f.gone[string(n.DeviceToken)] {
		return apns.Result{Status: 410, Reason: "Unregistered", Gone: true}, nil
	}
	return apns.Result{Status: 200}, nil
}

func (f *fakeApple) notifications() []apns.Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apns.Notification(nil), f.sent...)
}

// timers is a clock the test moves by hand.
type timers struct {
	mu  sync.Mutex
	now time.Time
	due []*timer
}

type timer struct {
	at      time.Time
	f       func()
	stopped bool
}

func (c *timers) after(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &timer{at: c.now.Add(d), f: f}
	c.due = append(c.due, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		was := !t.stopped
		t.stopped = true
		return was
	}
}

func (c *timers) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var fire []func()
	for _, t := range c.due {
		if !t.stopped && !t.at.After(c.now) {
			t.stopped = true
			fire = append(fire, t.f)
		}
	}
	c.mu.Unlock()
	for _, f := range fire {
		f()
	}
}

func (c *timers) time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

type rig struct {
	svc    *Service
	reg    *registry.Registry
	apple  *fakeApple
	clock  *timers
	home   string
	owner  cloudwire.Device
	viewer cloudwire.Device
	all    []string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	r := &rig{reg: reg, apple: &fakeApple{gone: map[string]bool{}},
		clock: &timers{now: time.Unix(1_791_820_800, 0)}, home: "fjzyr67buzpyncqmjliwgezvde"}
	r.svc = New(reg, r.apple, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.svc.now, r.svc.after = r.clock.time, r.clock.after
	if err := reg.Claim(r.home, []byte("pk"), r.clock.time()); err != nil {
		t.Fatal(err)
	}
	r.all = []string{protocol.ScopeLiveRead, protocol.ScopeEventsRead}
	r.owner = cloudwire.Device{ID: "owner-phone", Key: bytes.Repeat([]byte{5}, 32), Role: "owner", Scopes: r.all, Epoch: 1}
	r.viewer = cloudwire.Device{ID: "viewer-phone", Key: bytes.Repeat([]byte{6}, 32), Role: "viewer",
		Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1}
	return r
}

// drain runs what the uplink queued, as Run would.
func (r *rig) drain() {
	for {
		select {
		case job := <-r.svc.work:
			job(context.Background())
		default:
			return
		}
	}
}

func (r *rig) register(t *testing.T, dev cloudwire.Device, scopes []string, token string) error {
	t.Helper()
	return r.svc.Register(r.home, dev, scopes, cloudwire.PushRegister{
		APNsToken: []byte(token), Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert})
}

func TestAnEventGoesToRegisteredPhonesExactlyAsTheBoxSignedIt(t *testing.T) {
	r := newRig(t)
	if err := r.register(t, r.owner, r.all, "owner-token"); err != nil {
		t.Fatal(err)
	}
	envelope := []byte{0xa3, 0x61, 0x62, 0x41, 0x00, 0x61, 0x74, 0x65, 'e', 'v', 'e', 'n', 't', 0x63, 's', 'i', 'g', 0x40}
	r.svc.Event(r.home, envelope)
	r.drain()
	sent := r.apple.notifications()
	if len(sent) != 1 {
		t.Fatalf("sent %d", len(sent))
	}
	n := sent[0]
	want, _ := cloudwire.AlertPayload(cloudwire.Alert{Home: r.home, Event: envelope})
	if !bytes.Equal(n.Payload, want) || string(n.DeviceToken) != "owner-token" || n.Environment != apns.Sandbox {
		t.Fatalf("notification %+v", n)
	}
	var p struct {
		FTW cloudwire.Alert `json:"ftw"`
	}
	if json.Unmarshal(n.Payload, &p) != nil || !bytes.Equal(p.FTW.Event, envelope) {
		t.Fatal("the box's envelope did not arrive unchanged")
	}
	if !n.Expiration.Equal(r.clock.time().Add(10 * time.Minute)) {
		t.Fatalf("expires %v", n.Expiration)
	}
}

func TestOnlyADeviceThatMayReadEventsRegisters(t *testing.T) {
	r := newRig(t)
	if err := r.register(t, r.viewer, r.viewer.Scopes, "viewer-token"); err != ErrNotForThisDevice {
		t.Fatalf("a viewer registered: %v", err)
	}
	// An owner under a grant that leaves events out has no events scope
	// in its effective scope.
	if err := r.register(t, r.owner, []string{protocol.ScopeLiveRead}, "owner-token"); err != ErrNotForThisDevice {
		t.Fatalf("an owner without events registered: %v", err)
	}
	bad := []cloudwire.PushRegister{
		{APNsToken: []byte("t"), Environment: "staging", Kind: cloudwire.PushKindAlert},
		{APNsToken: []byte("t"), Environment: cloudwire.PushSandbox, Kind: "liveactivity"},
		{APNsToken: nil, Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert},
		{APNsToken: make([]byte, 101), Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert},
	}
	for _, b := range bad {
		if err := r.svc.Register(r.home, r.owner, r.all, b); err != ErrNotForThisDevice {
			t.Fatalf("registered %+v: %v", b, err)
		}
	}
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatalf("kept %d", len(regs))
	}
}

func TestASuspendedDeviceGetsNothingUntilTheSuspensionEnds(t *testing.T) {
	r := newRig(t)
	other := r.owner
	other.ID, other.Key = "other-owner", bytes.Repeat([]byte{7}, 32)
	if err := r.register(t, r.owner, r.all, "owner-token"); err != nil {
		t.Fatal(err)
	}
	if err := r.register(t, other, r.all, "other-token"); err != nil {
		t.Fatal(err)
	}
	if err := r.reg.Suspend(r.home, other.ID, other.Epoch, r.clock.time()); err != nil {
		t.Fatal(err)
	}
	tokens := func() []string {
		r.drain()
		var out []string
		for _, n := range r.apple.notifications() {
			out = append(out, string(n.DeviceToken))
		}
		r.apple.mu.Lock()
		r.apple.sent = nil
		r.apple.mu.Unlock()
		return out
	}

	r.svc.Event(r.home, []byte{0xa0})
	if got := tokens(); len(got) != 1 || got[0] != "owner-token" {
		t.Fatalf("while suspended, sent to %v", got)
	}
	// box.unreachable takes the same road.
	r.svc.BoxGone(r.home, "")
	r.clock.advance(10 * time.Minute)
	if got := tokens(); len(got) != 1 || got[0] != "owner-token" {
		t.Fatalf("unreachable went to %v", got)
	}

	if err := r.reg.Unsuspend(r.home, other.ID); err != nil {
		t.Fatal(err)
	}
	r.svc.Event(r.home, []byte{0xa0})
	if got := tokens(); len(got) != 2 {
		t.Fatalf("after the suspension ended, sent to %v", got)
	}
}

func TestARosterThatDropsOrNarrowsADeviceDropsItsTokens(t *testing.T) {
	r := newRig(t)
	other := r.owner
	other.ID, other.Key = "second-owner", bytes.Repeat([]byte{7}, 32)
	_ = r.register(t, r.owner, r.all, "a")
	_ = r.register(t, other, r.all, "b")
	grant := cloudwire.Grant{ID: bytes.Repeat([]byte{4}, 16), Scopes: r.all}

	// The second owner became a viewer: no events in its scopes.
	narrowed := other
	narrowed.Scopes, narrowed.Role = []string{protocol.ScopeLiveRead}, "viewer"
	r.svc.Roster(r.home, &cloudwire.Roster{Devices: []cloudwire.Device{r.owner, narrowed}, Grant: grant})
	regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert)
	if len(regs) != 1 || regs[0].DeviceID != r.owner.ID {
		t.Fatalf("after narrowing: %+v", regs)
	}
	// The owner paired again: a new epoch.
	again := r.owner
	again.Epoch = 2
	r.svc.Roster(r.home, &cloudwire.Roster{Devices: []cloudwire.Device{again}, Grant: grant})
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatalf("after a new epoch: %+v", regs)
	}
	// And a grant that drops events drops every token.
	_ = r.register(t, again, r.all, "c")
	grant.Scopes = []string{protocol.ScopeLiveRead}
	r.svc.Roster(r.home, &cloudwire.Roster{Devices: []cloudwire.Device{again}, Grant: grant})
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatalf("after the grant dropped events: %+v", regs)
	}
}

func TestATokenAppleSaysIsGoneIsForgotten(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "dead")
	r.apple.gone["dead"] = true
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatal("kept a token Apple called gone")
	}
}

func unreachableSent(t *testing.T, r *rig) int {
	t.Helper()
	r.drain()
	n := 0
	for _, x := range r.apple.notifications() {
		var p struct {
			FTW cloudwire.Alert `json:"ftw"`
		}
		if json.Unmarshal(x.Payload, &p) == nil && p.FTW.Kind == protocol.PushBoxUnreachable {
			if len(p.FTW.Event) != 0 || p.FTW.Home != r.home {
				t.Fatalf("unreachable payload %s", x.Payload)
			}
			n++
		}
	}
	return n
}

func TestBoxUnreachableAfterTenMinutesOncePerOutage(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, "")
	r.clock.advance(599 * time.Second)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatal("before ten minutes")
	}
	r.clock.advance(2 * time.Second)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d at ten minutes", n)
	}
	r.clock.advance(time.Hour)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("sent %d over one outage", n)
	}
	// Back and away again is a new outage.
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, cloudwire.ByeShutdown)
	r.clock.advance(601 * time.Second)
	if n := unreachableSent(t, r); n != 2 {
		t.Fatalf("sent %d over two outages", n)
	}
}

func TestABoxBackInTimeSaysNothing(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, "")
	r.clock.advance(5 * time.Minute)
	r.svc.BoxConnected(r.home)
	r.clock.advance(time.Hour)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatalf("sent %d for a box that came back", n)
	}
}

// A planned update sends nothing, unless the box is still away after an
// hour.
func TestAPlannedUpdateHoldsItBackForAnHour(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, cloudwire.ByeUpdate)
	r.clock.advance(20 * time.Minute)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatal("an update was reported as out of reach")
	}
	r.svc.BoxConnected(r.home)
	r.clock.advance(2 * time.Hour)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatal("an update that came back was reported")
	}

	r.svc.BoxGone(r.home, cloudwire.ByeUpdate)
	r.clock.advance(time.Hour + time.Second)
	if n := unreachableSent(t, r); n != 1 {
		t.Fatalf("an update still away after an hour: %d", n)
	}
}

func TestARevokedHomeHasNoDeadMan(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.BoxConnected(r.home)
	r.svc.BoxGone(r.home, cloudwire.ByeRevoked)
	r.clock.advance(2 * time.Hour)
	if n := unreachableSent(t, r); n != 0 {
		t.Fatal("a revoked home was reported out of reach")
	}
}

func TestAHomeCannotMakeItsPhonesBuzzWithoutEnd(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "tok")
	for range MaxAlertsPerHour + 5 {
		r.svc.Event(r.home, []byte{0xa0})
	}
	r.drain()
	if n := len(r.apple.notifications()); n != MaxAlertsPerHour {
		t.Fatalf("sent %d in an hour", n)
	}
	r.clock.advance(time.Hour)
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if n := len(r.apple.notifications()); n != MaxAlertsPerHour+1 {
		t.Fatalf("the cap did not lift after an hour: %d", n)
	}
}

func TestWithoutAKeyNothingIsSent(t *testing.T) {
	r := newRig(t)
	r.svc.sender = nil
	_ = r.register(t, r.owner, r.all, "tok")
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 1 {
		t.Fatal("registrations need no key")
	}
}
