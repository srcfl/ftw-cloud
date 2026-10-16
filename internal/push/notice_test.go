package push

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// holdRoster keeps a roster as the uplink does: signed in the registry, and
// heard by push.
func (r *rig) holdRoster(t *testing.T, seq uint64, grant cloudwire.Grant, devices ...cloudwire.Device) {
	t.Helper()
	roster := cloudwire.Roster{RosterSeq: seq, TTLS: 86_400, Devices: devices, Grant: grant}
	body, err := cloudwire.Marshal(roster)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cloudwire.Envelope{T: cloudwire.MsgRoster, B: body, Sig: make([]byte, 64)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.reg.SetRoster(r.home, seq, grant.ID, env, r.clock.time()); err != nil {
		t.Fatal(err)
	}
	r.svc.Roster(r.home, &roster)
}

// noticeEnvelope is a notice as the box signs it, with fields it should not
// carry when extra is set.
func noticeEnvelope(t *testing.T, kind string, extra map[string]any) []byte {
	t.Helper()
	body, err := cloudwire.Marshal(cloudwire.Notice{Header: cloudwire.Header{Seq: 7, Boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes),
		UptimeMs: 9_000}, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		var m map[string]any
		if err := cloudwire.Unmarshal(body, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range extra {
			m[k] = v
		}
		if body, err = cloudwire.Marshal(m); err != nil {
			t.Fatal(err)
		}
	}
	env, err := cloudwire.Envelope{T: cloudwire.MsgNotice, B: body, Sig: make([]byte, 64)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func tokens(sent []apns.Notification) []string {
	var out []string
	for _, n := range sent {
		out = append(out, string(n.DeviceToken))
	}
	slices.Sort(out)
	return out
}

// With the readable copy off, a notice reaches each owner phone once, as the
// box signed it, and no viewer or watch: they got their tokens while the copy
// carried events, and lost them with it.
func TestANoticeGoesToEachOwnerPhoneWithTheCopyOff(t *testing.T) {
	r := newRig(t)
	second := cloudwire.Device{ID: "second-owner", Key: bytes.Repeat([]byte{7}, 32), Role: protocol.RoleOwner, Scopes: r.all, Epoch: 3}
	viewer := r.viewer
	viewer.Scopes = r.all
	watch := cloudwire.Device{ID: "owner-watch", Key: bytes.Repeat([]byte{8}, 32), Role: "watch", Scopes: r.all, Epoch: 1}
	on := cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: r.all, Purposes: []string{protocol.CloudPurposeServe},
		Controller: cloudwire.ControllerSourceful}
	r.holdRoster(t, 1, on, r.owner, second, viewer, watch)
	for dev, token := range map[*cloudwire.Device]string{&r.owner: "owner-token", &second: "second-token", &viewer: "viewer-token"} {
		if err := r.register(t, *dev, r.all, token); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.svc.Register(r.home, watch, r.all, cloudwire.PushRegister{APNsToken: []byte("watch-token"),
		Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert, App: cloudwire.PushAppWatch}); err != nil {
		t.Fatal(err)
	}
	r.svc.WatchApp = "energy.ftw.app.watchkitapp"

	// With the copy on, a notice is still the owners' alone.
	r.svc.Notice(r.home, noticeEnvelope(t, protocol.PushAgentAdded, nil))
	r.drain()
	if got := tokens(r.apple.notifications()); !slices.Equal(got, []string{"owner-token", "second-token"}) {
		t.Fatalf("with the copy on, the notice went to %v", got)
	}

	// The copy goes off.
	r.holdRoster(t, 2, cloudwire.Grant{ID: on.ID, Controller: cloudwire.ControllerSourceful}, r.owner, second, viewer, watch)
	before := len(r.apple.notifications())
	envelope := noticeEnvelope(t, protocol.PushOwnerAdded, nil)
	r.svc.Notice(r.home, envelope)
	r.drain()
	sent := r.apple.notifications()[before:]
	if got := tokens(sent); !slices.Equal(got, []string{"owner-token", "second-token"}) {
		t.Fatalf("with the copy off, the notice went to %v", got)
	}
	want, _ := cloudwire.AlertPayload(cloudwire.Alert{Home: r.home, Event: envelope})
	for _, n := range sent {
		var p struct {
			FTW cloudwire.Alert `json:"ftw"`
		}
		if !bytes.Equal(n.Payload, want) || json.Unmarshal(n.Payload, &p) != nil || !bytes.Equal(p.FTW.Event, envelope) ||
			n.Type != apns.PushAlert || n.App != "" {
			t.Fatalf("notification %+v", n)
		}
	}
	// An event that arrives anyway goes to nobody: no device reads events
	// now.
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if len(r.apple.notifications()) != before+2 {
		t.Fatal("an event went out with the copy off")
	}
}

// An owner's phone registers for alerts with the copy off, to hear notices;
// a viewer, a watch and an owner's watch app do not.
func TestAnOwnersPhoneRegistersForNoticesWithTheCopyOff(t *testing.T) {
	r := newRig(t)
	if err := r.register(t, r.owner, nil, "owner-token"); err != nil {
		t.Fatalf("an owner's phone: %v", err)
	}
	if err := r.register(t, r.viewer, nil, "viewer-token"); err != ErrNotForThisDevice {
		t.Fatalf("a viewer registered: %v", err)
	}
	watch := cloudwire.Device{ID: "owner-watch", Key: bytes.Repeat([]byte{8}, 32), Role: "watch", Epoch: 1}
	if err := r.register(t, watch, nil, "watch-token"); err != ErrNotForThisDevice {
		t.Fatalf("a watch registered: %v", err)
	}
	if err := r.svc.Register(r.home, r.owner, nil, cloudwire.PushRegister{APNsToken: []byte("owner-watch-app"),
		Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert, App: cloudwire.PushAppWatch}); err != ErrNotForThisDevice {
		t.Fatalf("an owner's watch app registered: %v", err)
	}
	if err := r.svc.Register(r.home, r.owner, nil, cloudwire.PushRegister{APNsToken: []byte("w"),
		Environment: cloudwire.PushSandbox, Kind: KindWidgets}); err != ErrNotForThisDevice {
		t.Fatalf("an owner registered widgets without the copy: %v", err)
	}
	// A roster with the copy off keeps the owner's token.
	r.holdRoster(t, 1, cloudwire.Grant{Controller: cloudwire.ControllerSourceful}, r.owner, r.viewer)
	if regs, _ := r.reg.PushRegs(r.home, cloudwire.PushKindAlert); len(regs) != 1 || regs[0].DeviceID != r.owner.ID {
		t.Fatalf("kept %+v", regs)
	}
}

// A notice carries a kind and, on agent.added, the client's name. One that
// carries a reading, or anything that is not a notice, reaches nobody.
func TestANoticeCannotCarryReadings(t *testing.T) {
	r := newRig(t)
	r.holdRoster(t, 1, cloudwire.Grant{Controller: cloudwire.ControllerSourceful}, r.owner)
	if err := r.register(t, r.owner, nil, "owner-token"); err != nil {
		t.Fatal(err)
	}
	refused := noticesRefused.Load()
	for name, env := range map[string][]byte{
		"a reading":                noticeEnvelope(t, protocol.PushAgentRequest, map[string]any{"fields": map[int]int64{1: 2400}}),
		"a source id":              noticeEnvelope(t, protocol.PushAgentRequest, map[string]any{"src": "q5Lw0Zb1"}),
		"a kind that is no notice": noticeEnvelope(t, protocol.PushChargingConnected, nil),
		"not an envelope":          {0x01, 0x02},
	} {
		r.svc.Notice(r.home, env)
		r.drain()
		if n := len(r.apple.notifications()); n != 0 {
			t.Fatalf("%s: %d alerts", name, n)
		}
	}
	if got := noticesRefused.Load() - refused; got != 4 {
		t.Fatalf("counted %d refused notices", got)
	}
	// An event's envelope handed in as a notice is no notice either.
	event, _ := cloudwire.Envelope{T: cloudwire.MsgEvent, B: []byte{0xa0}, Sig: make([]byte, 64)}.Encode()
	r.svc.Notice(r.home, event)
	r.drain()
	if n := len(r.apple.notifications()); n != 0 {
		t.Fatalf("an event went as a notice: %d alerts", n)
	}
}

// Notices and events have caps of their own, so a home's events cannot
// crowd out the owners' notices.
func TestNoticesHaveTheirOwnCap(t *testing.T) {
	r := newRig(t)
	on := cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: r.all, Purposes: []string{protocol.CloudPurposeServe},
		Controller: cloudwire.ControllerSourceful}
	r.holdRoster(t, 1, on, r.owner)
	if err := r.register(t, r.owner, r.all, "owner-token"); err != nil {
		t.Fatal(err)
	}
	for range MaxAlertsPerHour + 1 {
		r.svc.Event(r.home, []byte{0xa0})
	}
	r.drain()
	if n := len(r.apple.notifications()); n != MaxAlertsPerHour {
		t.Fatalf("%d events went", n)
	}
	r.svc.Notice(r.home, noticeEnvelope(t, protocol.PushAgentRequest, nil))
	r.drain()
	if n := len(r.apple.notifications()); n != MaxAlertsPerHour+1 {
		t.Fatal("the events' cap held back a notice")
	}
}

// A box from before notices reached FTW Cloud sends an agent.added both as
// an event and as a notice. The event is dropped: it would reach a viewer,
// and the owners hear the notice.
func TestAnEventOfANoticeKindIsDropped(t *testing.T) {
	r := newRig(t)
	on := cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: r.all, Purposes: []string{protocol.CloudPurposeServe},
		Controller: cloudwire.ControllerSourceful}
	viewer := r.viewer
	viewer.Scopes = r.all
	r.holdRoster(t, 1, on, r.owner, viewer)
	_ = r.register(t, r.owner, r.all, "owner-token")
	_ = r.register(t, viewer, r.all, "viewer-token")
	event := func(kind string) []byte {
		body, err := cloudwire.Marshal(cloudwire.Event{Header: cloudwire.Header{Seq: 3, Boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes)},
			EventID: "e1", Kind: kind, Severity: cloudwire.SeverityInfo, Args: map[string]string{}})
		if err != nil {
			t.Fatal(err)
		}
		env, _ := cloudwire.Envelope{T: cloudwire.MsgEvent, B: body, Sig: make([]byte, 64)}.Encode()
		return env
	}
	refused := eventsRefused.Load()
	for _, kind := range cloudwire.NoticeKinds {
		r.svc.Event(r.home, event(kind))
	}
	r.drain()
	if n := len(r.apple.notifications()); n != 0 || eventsRefused.Load()-refused != int64(len(cloudwire.NoticeKinds)) {
		t.Fatalf("%d alerts, %d refused", n, eventsRefused.Load()-refused)
	}
	r.svc.Event(r.home, event(protocol.PushChargingConnected))
	r.drain()
	if got := tokens(r.apple.notifications()); !slices.Equal(got, []string{"owner-token", "viewer-token"}) {
		t.Fatalf("an ordinary event went to %v", got)
	}
}

// An owner an owner suspended gets no event, but still every notice: one
// owner must not silence another before adding an agent, a key or an owner.
func TestASuspendedOwnerStillGetsNotices(t *testing.T) {
	r := newRig(t)
	second := cloudwire.Device{ID: "second-owner", Key: bytes.Repeat([]byte{7}, 32), Role: protocol.RoleOwner, Scopes: r.all, Epoch: 3}
	on := cloudwire.Grant{ID: bytes.Repeat([]byte{5}, 16), Scopes: r.all, Purposes: []string{protocol.CloudPurposeServe},
		Controller: cloudwire.ControllerSourceful}
	r.holdRoster(t, 1, on, r.owner, second)
	_ = r.register(t, r.owner, r.all, "owner-token")
	_ = r.register(t, second, r.all, "second-token")
	if err := r.reg.Suspend(r.home, second.ID, second.Epoch, r.clock.time()); err != nil {
		t.Fatal(err)
	}
	r.svc.Event(r.home, []byte{0xa0})
	r.drain()
	if got := tokens(r.apple.notifications()); !slices.Equal(got, []string{"owner-token"}) {
		t.Fatalf("an event went to %v", got)
	}
	before := len(r.apple.notifications())
	r.svc.Notice(r.home, noticeEnvelope(t, protocol.PushOwnerAdded, nil))
	r.drain()
	if got := tokens(r.apple.notifications()[before:]); !slices.Equal(got, []string{"owner-token", "second-token"}) {
		t.Fatalf("the notice went to %v", got)
	}
	if n := r.apple.notifications()[before]; !n.Expiration.Equal(r.clock.time().Add(24 * time.Hour)) {
		t.Fatalf("a notice expires at %v", n.Expiration)
	}
}

// Apple takes at most 4 KB; a bigger alert never queues.
func TestAnAlertOverAPNsLimitIsDropped(t *testing.T) {
	r := newRig(t)
	_ = r.register(t, r.owner, r.all, "owner-token")
	big := tooLarge.Load()
	r.svc.Event(r.home, bytes.Repeat([]byte{0xa0}, 4000))
	r.drain()
	if n := len(r.apple.notifications()); n != 0 || tooLarge.Load()-big != 1 {
		t.Fatalf("%d alerts, %d too large", n, tooLarge.Load()-big)
	}
}
