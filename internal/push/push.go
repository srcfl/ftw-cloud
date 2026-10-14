// Package push tells a home's phones what its box said while they were not
// looking, through Apple. docs/protocol-cloud.md in srcfl/ftw, "Push", is the
// wire format; go/protocol/cloudwire builds the payload.
//
// The service chooses nothing a phone shows. An alert carries the box's
// signed event exactly as it arrived; the phone checks the signature, writes
// its own words and picks the buttons from the verified kind. Every alert
// has the same aps, priority and push type, and no collapse id, so the
// request says nothing a kind would. The one alert the service writes is
// box.unreachable, after the box has been away for ten minutes without
// saying it was restarting on purpose. It carries no arguments and no
// buttons.
//
// A widgets push carries no data. It tells WidgetKit to reload the app's
// widgets, which then read GET /v1/now with their own token. It goes when
// a box's priced hours reach further than before, as when tomorrow's prices
// arrive, and when a car is plugged in.
//
// Tokens are bound to roster entries. A device registers for alerts only if
// its role and the owner's grant both allow ftw.events.read, and for widgets
// only if they allow ftw.live.read. A roster that drops the device, moves
// its epoch or narrows its scope drops its tokens. A device an owner has
// suspended gets nothing until the suspension ends. Nothing here logs a
// token or a home id.
package push

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	// MaxAlertsPerHour bounds what one home can make its phones buzz. A box
	// raises a few notifications a day; past this, something is wrong and
	// the rest are dropped.
	MaxAlertsPerHour = 20
	// MaxTokensPerDevice bounds a device's registrations of one kind. A
	// phone holds one token per kind; a few more cover a reinstall before
	// Apple says the old token is gone. Past it the oldest goes, so one
	// device cannot fill the table or make a push call Apple without end.
	MaxTokensPerDevice = 4
	// MaxWidgetPushesPerHour bounds a home's widget pushes. Prices arrive
	// once a day and a car is plugged in a few times; Apple budgets widget
	// reloads, so a car that flaps between plugged and not must not spend
	// the budget.
	MaxWidgetPushesPerHour = 4
	// eventExpiry is how long Apple may keep trying to deliver an event.
	// Later than that the phone would show only the generic line.
	eventExpiry = cloudwire.AlertMaxAgeMs * time.Millisecond
	// unreachableExpiry is the same for box.unreachable, which stays true
	// while the box is away, and for a widgets push, which stays true until
	// the next change.
	unreachableExpiry = time.Hour
	widgetsExpiry     = time.Hour
	// queueSize bounds the alerts waiting to be sent.
	queueSize = 256
	// expireEvery is how often registrations of long-silent homes go.
	expireEvery = time.Hour
)

// KindWidgets registers a widget's push token. cloudwire names only
// PushKindAlert so far; the protocol's Push section names widgets.
const KindWidgets = "widgets"

// widgetsPayload is the whole widgets push, as Apple defines it.
var widgetsPayload = []byte(`{"aps":{"content-changed":true}}`)

// kind is what one kind of registration needs and how it goes to Apple.
type kind struct {
	scope    string
	pushType string
	perHour  int
}

var kinds = map[string]kind{
	cloudwire.PushKindAlert: {protocol.ScopeEventsRead, apns.PushAlert, MaxAlertsPerHour},
	KindWidgets:             {protocol.ScopeLiveRead, apns.PushWidgets, MaxWidgetPushesPerHour},
}

// Sender is Apple. apns.Client is one.
type Sender interface {
	Send(ctx context.Context, n apns.Notification) (apns.Result, error)
}

// ErrNotForThisDevice refuses a registration the device may not make: a
// device without the scope its kind needs, or a kind that does not exist
// yet. The app session goes on.
var ErrNotForThisDevice = errors.New("push: not a registration this device may make")

// Service keeps registrations and sends alerts.
type Service struct {
	reg    *registry.Registry
	sender Sender
	log    *slog.Logger
	now    func() time.Time
	// after runs f after d and returns a function that stops it. Tests
	// replace it.
	after func(d time.Duration, f func()) (stop func() bool)

	work chan func(context.Context)

	mu    sync.Mutex
	homes map[string]*homeState
}

// homeState is one home's box connection, as the dead man's switch sees it,
// its recent pushes per kind, and what its widgets show that can change.
type homeState struct {
	online bool
	// gen moves on every connect and disconnect, so a timer set for one
	// outage cannot fire into the next.
	gen  uint64
	stop func() bool
	told bool
	sent map[string][]time.Time
	// pricedUntil is where the newest prices end, 0 before the first.
	pricedUntil int64
	// plugged is each loadpoint's plug in the newest lp, nil before the
	// first.
	plugged map[string]bool
}

// New builds the service. A nil sender keeps registrations and sends
// nothing, for a service without an APNs key.
func New(reg *registry.Registry, sender Sender, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		reg: reg, sender: sender, log: log, now: time.Now,
		after: func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop },
		work:  make(chan func(context.Context), queueSize),
		homes: map[string]*homeState{},
	}
}

// Run sends queued alerts and drops long-silent registrations until ctx
// ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(expireEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-s.work:
			job(ctx)
		case <-t.C:
			if n, err := s.reg.PushExpire(s.now()); err != nil {
				s.log.Warn("push upkeep failed", "err", err)
			} else if n > 0 {
				s.log.Info("push registrations expired with their silent homes", "count", n)
			}
		}
	}
}

// enqueue hands a job to Run without ever blocking the caller, which is a
// box's uplink. A full queue drops the job.
func (s *Service) enqueue(job func(context.Context)) {
	select {
	case s.work <- job:
	default:
		s.log.Warn("push queue full; an alert was dropped")
	}
}

// --------------------------------------------------------------------------
// Registrations, from a phone's app session
// --------------------------------------------------------------------------

// Register keeps a device's APNs token. dev is the roster entry the phone's
// Noise key matched and scopes its effective scope, both from store.For.
func (s *Service) Register(home string, dev cloudwire.Device, scopes []string, r cloudwire.PushRegister) error {
	k, known := kinds[r.Kind]
	if !known || !slices.Contains(scopes, k.scope) ||
		len(r.APNsToken) == 0 || len(r.APNsToken) > cloudwire.APNsTokenMaxBytes ||
		(r.Environment != cloudwire.PushSandbox && r.Environment != cloudwire.PushProduction) {
		return ErrNotForThisDevice
	}
	if err := s.reg.PushRegister(registry.PushReg{Home: home, DeviceID: dev.ID, Epoch: dev.Epoch,
		Token: r.APNsToken, Environment: r.Environment, Kind: r.Kind, At: s.now()}); err != nil {
		return err
	}
	return s.reg.PushTrim(home, dev.ID, r.Kind, MaxTokensPerDevice)
}

// Unregister forgets one of the device's tokens.
func (s *Service) Unregister(home string, dev cloudwire.Device, r cloudwire.PushUnregister) error {
	return s.reg.PushUnregister(home, dev.ID, r.APNsToken)
}

// --------------------------------------------------------------------------
// From a box's uplink. None of these blocks.
// --------------------------------------------------------------------------

// Roster drops the tokens of devices the box's roster no longer lets read
// what their kind carries: gone, paired again under a new epoch, or
// narrowed.
func (s *Service) Roster(home string, r *cloudwire.Roster) {
	if r == nil {
		return
	}
	devices := make(map[string]cloudwire.Device, len(r.Devices))
	for _, d := range r.Devices {
		devices[d.ID] = d
	}
	if err := s.reg.PushPrune(home, func(id string, epoch uint64, kindName string) bool {
		d, ok := devices[id]
		k, known := kinds[kindName]
		return ok && known && d.Epoch == epoch && slices.Contains(d.Scopes, k.scope) && slices.Contains(r.Grant.Scopes, k.scope)
	}); err != nil {
		s.log.Warn("could not drop the tokens a roster dropped", "err", err)
	}
}

// Held gets every envelope the service holds, after the uplink checked the
// box's signature: an event goes out as an alert, and new prices or a car
// plugged in send a widgets push.
func (s *Service) Held(home, class string, envelope []byte) {
	switch class {
	case cloudwire.MsgEvent:
		s.Event(home, envelope)
	case cloudwire.MsgPrices, cloudwire.MsgLP:
		if s.widgetsChanged(home, class, envelope) {
			s.enqueue(func(ctx context.Context) { s.send(ctx, home, KindWidgets, widgetsPayload, widgetsExpiry) })
		}
	}
}

// Event sends a box-signed event envelope, as it arrived, to the home's
// registered phones.
func (s *Service) Event(home string, envelope []byte) {
	payload, err := cloudwire.AlertPayload(cloudwire.Alert{Home: home, Event: envelope})
	if err != nil {
		return
	}
	s.enqueue(func(ctx context.Context) { s.send(ctx, home, cloudwire.PushKindAlert, payload, eventExpiry) })
}

// widgetsChanged reports whether prices now reach further than before, or a
// loadpoint is plugged in that was not. The first of each after a restart
// only sets what the next is compared with.
func (s *Service) widgetsChanged(home, class string, envelope []byte) bool {
	env, err := cloudwire.DecodeEnvelope(envelope)
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(home)
	switch class {
	case cloudwire.MsgPrices:
		var p cloudwire.Prices
		if cloudwire.Unmarshal(env.B, &p) != nil {
			return false
		}
		until := pricedUntil(p)
		changed := st.pricedUntil != 0 && until > st.pricedUntil
		if until > st.pricedUntil {
			st.pricedUntil = until
		}
		return changed
	default:
		var lp cloudwire.LP
		if cloudwire.Unmarshal(env.B, &lp) != nil {
			return false
		}
		plugged := make(map[string]bool, len(lp.Loadpoints))
		changed := false
		for _, l := range lp.Loadpoints {
			plugged[l.ID] = l.Plugged
			changed = changed || (st.plugged != nil && l.Plugged && !st.plugged[l.ID])
		}
		st.plugged = plugged
		return changed
	}
}

// pricedUntil is where the last priced slot ends.
func pricedUntil(p cloudwire.Prices) int64 {
	last := -1
	for i := range max(len(p.SpotMinor), len(p.TotalMinor)) {
		if i < len(p.SpotMinor) && p.SpotMinor[i] != nil || i < len(p.TotalMinor) && p.TotalMinor[i] != nil {
			last = i
		}
	}
	if last < 0 || p.SlotMs <= 0 {
		return 0
	}
	return p.T0Ms + int64(last+1)*p.SlotMs
}

// BoxConnected stops the dead man's switch for a home whose box is back.
func (s *Service) BoxConnected(home string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(home)
	st.gen++
	st.online, st.told = true, false
	if st.stop != nil {
		st.stop()
		st.stop = nil
	}
}

// BoxGone starts the dead man's switch. why is the box's bye reason, empty
// when the socket just dropped. A bye for an update holds box.unreachable
// back until the box has been away for cloudwire.UpdateGraceMs; a revoke
// ends it, since the home is gone.
func (s *Service) BoxGone(home, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if why == cloudwire.ByeRevoked {
		if st := s.homes[home]; st != nil && st.stop != nil {
			st.stop()
		}
		delete(s.homes, home)
		return
	}
	st := s.state(home)
	st.gen++
	st.online = false
	if st.stop != nil {
		st.stop()
	}
	wait := time.Duration(cloudwire.UnreachableAfterMs) * time.Millisecond
	if why == cloudwire.ByeUpdate {
		wait = time.Duration(cloudwire.UpdateGraceMs) * time.Millisecond
	}
	s.log.Info("a box went away", "bye", why, "out_of_reach_after", wait)
	gen := st.gen
	st.stop = s.after(wait, func() { s.unreachable(home, gen) })
}

func (s *Service) unreachable(home string, gen uint64) {
	s.mu.Lock()
	st := s.homes[home]
	if st == nil || st.gen != gen || st.online || st.told {
		s.mu.Unlock()
		return
	}
	st.told, st.stop = true, nil
	s.mu.Unlock()
	s.log.Info("a box is out of reach; telling its phones")
	payload, err := cloudwire.AlertPayload(cloudwire.Alert{Home: home, Kind: protocol.PushBoxUnreachable})
	if err != nil {
		return
	}
	s.enqueue(func(ctx context.Context) { s.send(ctx, home, cloudwire.PushKindAlert, payload, unreachableExpiry) })
}

func (s *Service) state(home string) *homeState {
	st := s.homes[home]
	if st == nil {
		st = &homeState{sent: map[string][]time.Time{}}
		s.homes[home] = st
	}
	return st
}

// allow counts one push of a kind against the home's hourly cap.
func (s *Service) allow(home, kindName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(home)
	now := s.now()
	var keep []time.Time
	for _, at := range st.sent[kindName] {
		if now.Sub(at) < time.Hour {
			keep = append(keep, at)
		}
	}
	if len(keep) >= kinds[kindName].perHour {
		st.sent[kindName] = keep
		return false
	}
	st.sent[kindName] = append(keep, now)
	return true
}

// send posts one payload to every device of the home registered for a kind,
// and forgets the tokens Apple says are gone.
func (s *Service) send(ctx context.Context, home, kindName string, payload []byte, expiry time.Duration) {
	if s.sender == nil {
		return
	}
	regs, err := s.reg.PushRegs(home, kindName)
	if err != nil {
		s.log.Warn("could not read push registrations", "err", err)
		return
	}
	// A device an owner has suspended keeps its tokens, so lifting the
	// suspension brings its alerts back, but gets nothing meanwhile.
	regs = slices.DeleteFunc(regs, func(r registry.PushReg) bool {
		return s.reg.Suspended(home, r.DeviceID, r.Epoch)
	})
	if len(regs) == 0 {
		return
	}
	k := kinds[kindName]
	if !s.allow(home, kindName) {
		s.log.Warn("a home passed its push cap; push dropped", "kind", kindName, "cap_per_hour", k.perHour)
		return
	}
	var sent, gone, failed int
	exp := s.now().Add(expiry)
	for _, r := range regs {
		res, err := s.sender.Send(ctx, apns.Notification{Environment: r.Environment, DeviceToken: r.Token,
			Type: k.pushType, Payload: payload, Expiration: exp})
		switch {
		case err != nil:
			failed++
		case res.OK():
			sent++
		case res.Gone:
			gone++
			if err := s.reg.PushGone(home, r.Token, kindName, res.GoneSince); err != nil {
				s.log.Warn("could not forget a gone token", "err", err)
			}
		default:
			failed++
			s.log.Warn("APNs refused a push", "kind", kindName, "status", res.Status, "reason", res.Reason)
		}
	}
	s.log.Info("push sent", "kind", kindName, "devices", sent, "gone", gone, "failed", failed)
}
