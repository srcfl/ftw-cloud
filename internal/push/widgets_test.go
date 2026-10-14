package push

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	day  = int64(24 * 3600 * 1000)
	hour = int64(3600 * 1000)
)

// boxSigner signs the prices and lp a box sends, so the service reads them
// as the uplink hands them over.
type boxSigner struct {
	t   *testing.T
	key *ecdsa.PrivateKey
	seq uint64
}

func newBoxSigner(t *testing.T) *boxSigner {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &boxSigner{t: t, key: key}
}

func (b *boxSigner) envelope(home, class string, body any) []byte {
	b.t.Helper()
	env, err := cloudwire.Seal(b.key, home, class, body)
	if err != nil {
		b.t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		b.t.Fatal(err)
	}
	return raw
}

func (b *boxSigner) header() cloudwire.Header {
	b.seq++
	return cloudwire.Header{Seq: b.seq, Boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes)}
}

// prices covers n hourly slots from t0, priced up to the slot priced.
func (b *boxSigner) prices(home string, t0 int64, n, priced int) []byte {
	p := cloudwire.Prices{Header: b.header(), Zone: "SE3", Currency: "SEK", T0Ms: t0, SlotMs: hour,
		SpotMinor: make([]*int64, n), TotalMinor: make([]*int64, n)}
	for i := range priced {
		v := int64(100 + i)
		p.SpotMinor[i], p.TotalMinor[i] = &v, &v
	}
	return b.envelope(home, cloudwire.MsgPrices, p)
}

func (b *boxSigner) lp(home string, plugged ...bool) []byte {
	l := cloudwire.LP{Header: b.header(), Loadpoints: []cloudwire.Loadpoint{}, Feedback: []cloudwire.Feedback{}}
	for i, p := range plugged {
		l.Loadpoints = append(l.Loadpoints, cloudwire.Loadpoint{ID: string(rune('a' + i)), Src: "src", Plugged: p})
	}
	return b.envelope(home, cloudwire.MsgLP, l)
}

func (r *rig) registerWidgets(t *testing.T, dev cloudwire.Device, scopes []string, token string) error {
	t.Helper()
	return r.svc.Register(r.home, dev, scopes, cloudwire.PushRegister{
		APNsToken: []byte(token), Environment: cloudwire.PushSandbox, Kind: KindWidgets})
}

// taken returns what went to Apple since the last call.
func (r *rig) taken() []apns.Notification {
	r.drain()
	r.apple.mu.Lock()
	defer r.apple.mu.Unlock()
	out := r.apple.sent
	r.apple.sent = nil
	return out
}

// A widget registers with ftw.live.read, as a viewer's may; alerts still need
// ftw.events.read.
func TestAWidgetRegistersWithLiveRead(t *testing.T) {
	r := newRig(t)
	if err := r.registerWidgets(t, r.viewer, r.viewer.Scopes, "viewer-widgets"); err != nil {
		t.Fatalf("a viewer's widget: %v", err)
	}
	if err := r.registerWidgets(t, r.owner, []string{protocol.ScopeEventsRead}, "no-live"); err != ErrNotForThisDevice {
		t.Fatalf("a device without live read registered a widget: %v", err)
	}
	regs, _ := r.reg.PushRegs(r.home, KindWidgets)
	if len(regs) != 1 || regs[0].DeviceID != r.viewer.ID {
		t.Fatalf("widgets %+v", regs)
	}
	if alerts, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(alerts) != 0 {
		t.Fatal("a widget registration became an alert")
	}
}

// Prices that reach further than before, as when tomorrow's arrive, send one
// widgets push to the widgets and nothing to the alerts. The first prices
// after a start, a resend and the shift at midnight send nothing.
func TestTomorrowsPricesReloadTheWidgets(t *testing.T) {
	r := newRig(t)
	box := newBoxSigner(t)
	_ = r.register(t, r.owner, r.all, "owner-alerts")
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	_ = r.registerWidgets(t, r.viewer, r.viewer.Scopes, "viewer-widgets")
	today := int64(1_791_756_000_000)

	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, today, 48, 24))
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, today, 48, 24))
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("today's prices sent %d", len(got))
	}
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, today, 48, 48))
	got := r.taken()
	if len(got) != 2 {
		t.Fatalf("tomorrow's prices went to %d devices", len(got))
	}
	for _, n := range got {
		if n.Type != apns.PushWidgets || string(n.Payload) != `{"aps":{"content-changed":true}}` ||
			!bytes.HasSuffix(n.DeviceToken, []byte("-widgets")) {
			t.Fatalf("push %+v", n)
		}
	}
	// Midnight: the day moves on, and the priced hours end where they did.
	r.svc.Held(r.home, cloudwire.MsgPrices, box.prices(r.home, today+day, 24, 24))
	if got := r.taken(); len(got) != 0 {
		t.Fatalf("midnight sent %d", len(got))
	}
}

// A car plugged in sends one widgets push. Staying plugged, unplugging and
// the first lp after a start send nothing.
func TestACarPluggedInReloadsTheWidgets(t *testing.T) {
	r := newRig(t)
	box := newBoxSigner(t)
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	for i, step := range []struct {
		plugged []bool
		pushes  int
	}{
		{[]bool{true, false}, 0}, // the first lp only sets what the next is compared with
		{[]bool{true, false}, 0},
		{[]bool{true, true}, 1},
		{[]bool{false, true}, 0},
		{[]bool{true, true}, 1},
	} {
		r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, step.plugged...))
		if got := r.taken(); len(got) != step.pushes {
			t.Fatalf("step %d sent %d", i, len(got))
		}
	}
}

// A car that flaps between plugged and not cannot spend Apple's budget for
// the home's widgets.
func TestWidgetPushesAreCappedPerHome(t *testing.T) {
	r := newRig(t)
	box := newBoxSigner(t)
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, false))
	sent := 0
	for range MaxWidgetPushesPerHour + 3 {
		r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, true))
		r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, false))
		sent += len(r.taken())
	}
	if sent != MaxWidgetPushesPerHour {
		t.Fatalf("sent %d in an hour", sent)
	}
	r.clock.advance(time.Hour)
	r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, true))
	if got := r.taken(); len(got) != 1 {
		t.Fatalf("the cap did not lift after an hour: %d", len(got))
	}
	// The alert cap is its own.
	_ = r.register(t, r.owner, r.all, "owner-alerts")
	r.svc.Event(r.home, []byte{0xa0})
	if got := r.taken(); len(got) != 1 || got[0].Type != apns.PushAlert {
		t.Fatalf("an alert after the widgets: %+v", got)
	}
}

// A roster prunes each kind by its own scope: a device that loses events
// keeps its widgets, and one that loses live loses them.
func TestARosterPrunesEachKindByItsScope(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "alerts")
	_ = r.registerWidgets(t, r.owner, r.all, "widgets")
	grant := cloudwire.Grant{ID: bytes.Repeat([]byte{4}, 16), Scopes: r.all}
	count := func(kind string) int {
		regs, _ := r.reg.PushRegs(r.home, kind)
		return len(regs)
	}
	noEvents := r.owner
	noEvents.Scopes = []string{protocol.ScopeLiveRead}
	r.svc.Roster(r.home, &cloudwire.Roster{Devices: []cloudwire.Device{noEvents}, Grant: grant})
	if count(cloudwire.PushKindAlert) != 0 || count(KindWidgets) != 1 {
		t.Fatal("losing events did not drop alerts alone")
	}
	grant.Scopes = []string{protocol.ScopeEventsRead}
	r.svc.Roster(r.home, &cloudwire.Roster{Devices: []cloudwire.Device{r.owner}, Grant: grant})
	if count(KindWidgets) != 0 {
		t.Fatal("a grant without live kept the widgets")
	}
}

// A suspended device's widgets get nothing, as its alerts get nothing.
func TestASuspendedDevicesWidgetsGetNothing(t *testing.T) {
	r := newRig(t)
	box := newBoxSigner(t)
	_ = r.registerWidgets(t, r.owner, r.all, "owner-widgets")
	_ = r.registerWidgets(t, r.viewer, r.viewer.Scopes, "viewer-widgets")
	_ = r.reg.Suspend(r.home, r.viewer.ID, r.viewer.Epoch, r.clock.time())
	r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, false))
	r.svc.Held(r.home, cloudwire.MsgLP, box.lp(r.home, true))
	if got := r.taken(); len(got) != 1 || string(got[0].DeviceToken) != "owner-widgets" {
		t.Fatalf("sent to %+v", got)
	}
}
