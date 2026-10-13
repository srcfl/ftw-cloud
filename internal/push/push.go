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
// Tokens are bound to roster entries. Only a device whose role and the
// owner's grant both allow ftw.events.read may register, and a roster that
// drops the device, moves its epoch or narrows its scope drops its tokens.
// Nothing here logs a token or a home id.
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
	// eventExpiry is how long Apple may keep trying to deliver an event.
	// Later than that the phone would show only the generic line.
	eventExpiry = cloudwire.AlertMaxAgeMs * time.Millisecond
	// unreachableExpiry is the same for box.unreachable, which stays true
	// while the box is away.
	unreachableExpiry = time.Hour
	// queueSize bounds the alerts waiting to be sent.
	queueSize = 256
	// expireEvery is how often registrations of long-silent homes go.
	expireEvery = time.Hour
)

// Sender is Apple. apns.Client is one.
type Sender interface {
	Send(ctx context.Context, n apns.Notification) (apns.Result, error)
}

// ErrNotForThisDevice refuses a registration the device may not make: a
// viewer, a grant without events, or a kind that does not exist yet. The
// app session goes on.
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
// and its recent alerts.
type homeState struct {
	online bool
	// gen moves on every connect and disconnect, so a timer set for one
	// outage cannot fire into the next.
	gen  uint64
	stop func() bool
	told bool
	sent []time.Time
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
	if r.Kind != cloudwire.PushKindAlert || !slices.Contains(scopes, protocol.ScopeEventsRead) ||
		len(r.APNsToken) == 0 || len(r.APNsToken) > cloudwire.APNsTokenMaxBytes ||
		(r.Environment != cloudwire.PushSandbox && r.Environment != cloudwire.PushProduction) {
		return ErrNotForThisDevice
	}
	return s.reg.PushRegister(registry.PushReg{Home: home, DeviceID: dev.ID, Epoch: dev.Epoch,
		Token: r.APNsToken, Environment: r.Environment, Kind: r.Kind, At: s.now()})
}

// Unregister forgets one of the device's tokens.
func (s *Service) Unregister(home string, dev cloudwire.Device, r cloudwire.PushUnregister) error {
	return s.reg.PushUnregister(home, dev.ID, r.APNsToken)
}

// --------------------------------------------------------------------------
// From a box's uplink. None of these blocks.
// --------------------------------------------------------------------------

// Roster drops the tokens of devices the box's roster no longer lets read
// events: gone, paired again under a new epoch, or narrowed.
func (s *Service) Roster(home string, r *cloudwire.Roster) {
	if r == nil {
		return
	}
	allowed := map[string]uint64{}
	for _, d := range r.Devices {
		if slices.Contains(d.Scopes, protocol.ScopeEventsRead) && slices.Contains(r.Grant.Scopes, protocol.ScopeEventsRead) {
			allowed[d.ID] = d.Epoch
		}
	}
	if err := s.reg.PushPrune(home, func(id string, epoch uint64) bool {
		e, ok := allowed[id]
		return ok && e == epoch
	}); err != nil {
		s.log.Warn("could not drop the tokens a roster dropped", "err", err)
	}
}

// Event sends a box-signed event envelope, as it arrived, to the home's
// registered phones.
func (s *Service) Event(home string, envelope []byte) {
	payload, err := cloudwire.AlertPayload(cloudwire.Alert{Home: home, Event: envelope})
	if err != nil {
		return
	}
	s.enqueue(func(ctx context.Context) { s.send(ctx, home, payload, eventExpiry) })
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
	payload, err := cloudwire.AlertPayload(cloudwire.Alert{Home: home, Kind: protocol.PushBoxUnreachable})
	if err != nil {
		return
	}
	s.enqueue(func(ctx context.Context) { s.send(ctx, home, payload, unreachableExpiry) })
}

func (s *Service) state(home string) *homeState {
	st := s.homes[home]
	if st == nil {
		st = &homeState{}
		s.homes[home] = st
	}
	return st
}

// allow counts one alert against the home's hourly cap.
func (s *Service) allow(home string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(home)
	now := s.now()
	keep := st.sent[:0]
	for _, at := range st.sent {
		if now.Sub(at) < time.Hour {
			keep = append(keep, at)
		}
	}
	st.sent = keep
	if len(st.sent) >= MaxAlertsPerHour {
		return false
	}
	st.sent = append(st.sent, now)
	return true
}

// send posts one payload to every phone of the home registered for alerts,
// and forgets the tokens Apple says are gone.
func (s *Service) send(ctx context.Context, home string, payload []byte, expiry time.Duration) {
	if s.sender == nil {
		return
	}
	regs, err := s.reg.PushRegs(home, cloudwire.PushKindAlert)
	if err != nil {
		s.log.Warn("could not read push registrations", "err", err)
		return
	}
	if len(regs) == 0 {
		return
	}
	if !s.allow(home) {
		s.log.Warn("a home passed its alert cap; alert dropped", "cap_per_hour", MaxAlertsPerHour)
		return
	}
	var sent, gone, failed int
	exp := s.now().Add(expiry)
	for _, r := range regs {
		res, err := s.sender.Send(ctx, apns.Notification{Environment: r.Environment, DeviceToken: r.Token,
			Payload: payload, Expiration: exp})
		switch {
		case err != nil:
			failed++
		case res.OK():
			sent++
		case res.Gone:
			gone++
			if err := s.reg.PushGone(home, r.Token, res.GoneSince); err != nil {
				s.log.Warn("could not forget a gone token", "err", err)
			}
		default:
			failed++
			s.log.Warn("APNs refused an alert", "status", res.Status, "reason", res.Reason)
		}
	}
	s.log.Info("alert sent", "phones", sent, "gone", gone, "failed", failed)
}
