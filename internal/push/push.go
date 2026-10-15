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
//
// A watch registers its own tokens with app watch (ADR 0009). Its pushes go
// to the watch app's topic, and an alert carries the same payload, byte for
// byte, as its phone's, so Apple shows one when both are near.
package push

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/metrics"
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
	// expireEvery is how often registrations of long-silent homes go.
	expireEvery = time.Hour

	// AlertWorkers send alerts side by side over Apple's HTTP/2
	// connections, so one slow answer from Apple holds up one alert, not
	// every home's.
	AlertWorkers = 4
	// MaxAlertsQueued bounds the alerts waiting. It is far above a burst
	// of box.unreachable for every home at once; past it an alert is
	// dropped, logged and counted, never silently.
	MaxAlertsQueued = 50_000
	// alertTries is how often one alert goes to Apple when Apple or the
	// network fails for a while, each after twice the last wait from
	// alertRetryAfter, while the alert is still worth showing.
	alertTries      = 4
	alertRetryAfter = 2 * time.Second
	// WidgetHomesPerSecond and widgetBurst bound widget pushes over all
	// homes. Tomorrow's prices reach every box within a minute or so;
	// this turns that into a steady stream to Apple, which keeps alerts
	// quick, and Apple budgets widget reloads per phone anyway.
	WidgetHomesPerSecond = 20
	widgetBurst          = 40
	// maxWidgetsQueued bounds the homes waiting for a widgets push. A home
	// waits at most once: a second change before its push goes is the
	// same push.
	maxWidgetsQueued = 100_000
)

// Drops, queue depths and Apple's answers, summed over all homes.
var (
	alertsQueued   = metrics.Default.Gauge("ftwcloud_push_queued", "Pushes waiting for a worker.", "kind", "alert")
	widgetsQueued  = metrics.Default.Gauge("ftwcloud_push_queued", "Pushes waiting for a worker.", "kind", "widgets")
	alertsDropped  = metrics.Drop("push_alert_queue_full")
	widgetsDropped = metrics.Drop("push_widgets_queue_full")
	widgetsMerged  = metrics.Default.Counter("ftwcloud_push_coalesced_total", "Widget pushes merged into one already waiting.")
	pushCapped     = metrics.Drop("push_home_cap")
	apnsResults    = map[string]map[string]*metrics.Counter{}
)

func init() {
	for _, k := range []string{cloudwire.PushKindAlert, KindWidgets} {
		apnsResults[k] = map[string]*metrics.Counter{}
		for _, r := range []string{"ok", "gone", "refused", "retry", "failed"} {
			apnsResults[k][r] = metrics.Default.Counter("ftwcloud_apns_total", "Apple's answers per device, by kind and result.", "kind", k, "result", r)
		}
	}
}

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

	// WatchApp is the watch app's bundle id, the APNs topic for tokens
	// registered with app watch. Empty sends them nothing. The iPhone app's
	// is the sender's own. Set before serving.
	WatchApp string
	// Owns reports whether this shard holds a home. Resume starts no
	// box.unreachable for a home another shard holds, whose rows may still
	// be here during a move. Nil holds every home. Set before Resume.
	Owns func(home string) bool
	// after runs f after d and returns a function that stops it. Tests
	// replace it.
	after func(d time.Duration, f func()) (stop func() bool)

	// alerts wait for AlertWorkers; widgets for the one widget worker,
	// each home once. busy counts the workers taking or sending an alert,
	// and retrying the alerts waiting to go again.
	alerts   *fifo[alertJob]
	widgets  *fifo[string]
	busy     atomic.Int64
	retrying atomic.Int64
	gate     gate

	mu    sync.Mutex
	homes map[string]*homeState
	// widgetWaiting is the homes queued in widgets.
	widgetWaiting map[string]bool
}

// alertJob is one alert to a home's phones. On a retry, regs holds the
// registrations Apple did not take, and tries how often it went.
type alertJob struct {
	home    string
	payload []byte
	expires time.Time
	tries   int
	regs    []registry.PushReg
}

// homeState is one home's box connection, as the dead man's switch sees it,
// its recent pushes per kind, and what its widgets show that can change.
type homeState struct {
	online bool
	// gen moves on every connect and disconnect, so a timer set for one
	// outage cannot fire into the next. conn is the newest uplink
	// connection heard of, so the end of an older one, heard late, does
	// not start the switch for a box that is back.
	gen  uint64
	conn uint64
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
		after:         func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop },
		alerts:        newFIFO[alertJob](MaxAlertsQueued, alertsQueued),
		widgets:       newFIFO[string](maxWidgetsQueued, widgetsQueued),
		gate:          gate{rate: WidgetHomesPerSecond, burst: widgetBurst, tokens: widgetBurst},
		homes:         map[string]*homeState{},
		widgetWaiting: map[string]bool{},
	}
}

// Run sends queued pushes and drops long-silent registrations until ctx
// ends: AlertWorkers send alerts, and one worker sends widget pushes at
// WidgetHomesPerSecond.
func (s *Service) Run(ctx context.Context) {
	for range AlertWorkers {
		go s.alertWorker(ctx)
	}
	go s.widgetWorker(ctx)
	t := time.NewTicker(expireEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.reg.PushExpire(s.now()); err != nil {
				s.log.Warn("push upkeep failed", "err", err)
			} else if n > 0 {
				s.log.Info("push registrations expired with their silent homes", "count", n)
			}
		}
	}
}

func (s *Service) alertWorker(ctx context.Context) {
	for {
		// busy rises before the pop, so Flush never sees an alert that is
		// in neither the queue nor a worker.
		s.busy.Add(1)
		job, ok := s.alerts.pop()
		if !ok {
			s.busy.Add(-1)
			select {
			case <-ctx.Done():
				return
			case <-s.alerts.wake:
			}
			continue
		}
		s.sendAlert(ctx, job)
		s.busy.Add(-1)
	}
}

func (s *Service) widgetWorker(ctx context.Context) {
	for {
		home, ok := s.widgets.pop()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-s.widgets.wake:
			}
			continue
		}
		s.mu.Lock()
		delete(s.widgetWaiting, home)
		s.mu.Unlock()
		if !s.gate.wait(ctx) {
			return
		}
		s.sendWidgets(ctx, home)
	}
}

// Flush waits until no alert is queued, being sent or waiting to go again,
// at most d, and returns how many were left. Widget pushes may be left; the
// next change sends them.
func (s *Service) Flush(d time.Duration) int {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if s.alerts.len() == 0 && s.busy.Load() == 0 && s.retrying.Load() == 0 {
			return 0
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s.alerts.len() + int(s.retrying.Load())
}

// queueAlert hands an alert to the workers without ever blocking the
// caller, which is a box's uplink.
func (s *Service) queueAlert(job alertJob) {
	if !s.alerts.push(job) {
		alertsDropped.Inc()
		s.log.Error("push: the alert queue is full; an alert was dropped", "queued", s.alerts.len())
	}
}

// queueWidgets asks for a widgets push to a home, once however many changes
// arrive before it goes.
func (s *Service) queueWidgets(home string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.widgetWaiting[home] {
		widgetsMerged.Inc()
		return
	}
	if !s.widgets.push(home) {
		widgetsDropped.Inc()
		return
	}
	s.widgetWaiting[home] = true
}

// --------------------------------------------------------------------------
// Registrations, from a phone's app session
// --------------------------------------------------------------------------

// Register keeps a device's APNs token. dev is the roster entry the phone's
// Noise key matched and scopes its effective scope, both from store.For.
func (s *Service) Register(home string, dev cloudwire.Device, scopes []string, r cloudwire.PushRegister) error {
	k, known := kinds[r.Kind]
	app := r.App
	if app == "" {
		app = cloudwire.PushAppIPhone
	}
	if !known || !slices.Contains(scopes, k.scope) ||
		(app != cloudwire.PushAppIPhone && app != cloudwire.PushAppWatch) ||
		len(r.APNsToken) == 0 || len(r.APNsToken) > cloudwire.APNsTokenMaxBytes ||
		(r.Environment != cloudwire.PushSandbox && r.Environment != cloudwire.PushProduction) {
		return ErrNotForThisDevice
	}
	if err := s.reg.PushRegister(registry.PushReg{Home: home, DeviceID: dev.ID, Epoch: dev.Epoch,
		Token: r.APNsToken, Environment: r.Environment, Kind: r.Kind, App: app, At: s.now()}); err != nil {
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
			s.queueWidgets(home)
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
	s.queueAlert(alertJob{home: home, payload: payload, expires: s.now().Add(eventExpiry)})
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
// conn is the uplink's connection number for the home, which rises with
// every connection.
func (s *Service) BoxConnected(home string, conn uint64) {
	s.mu.Lock()
	st := s.state(home)
	if conn < st.conn {
		s.mu.Unlock()
		return
	}
	st.conn = conn
	st.gen++
	st.online, st.told = true, false
	if st.stop != nil {
		st.stop()
		st.stop = nil
	}
	s.mu.Unlock()
	if err := s.reg.AwayClear(home); err != nil {
		s.log.Warn("could not record a box's return", "err", err)
	}
}

// BoxGone starts the dead man's switch. why is the box's bye reason, empty
// when the socket just dropped. A bye for an update holds box.unreachable
// back until the box has been away for cloudwire.UpdateGraceMs; a revoke
// ends it, since the home is gone. The end of a connection older than one
// already back is ignored.
func (s *Service) BoxGone(home, why string, conn uint64) {
	s.mu.Lock()
	stale := s.homes[home] != nil && conn < s.homes[home].conn
	s.mu.Unlock()
	if stale {
		return
	}
	if why == cloudwire.ByeRevoked {
		s.mu.Lock()
		if st := s.homes[home]; st != nil && st.stop != nil {
			st.stop()
		}
		delete(s.homes, home)
		s.mu.Unlock()
		if err := s.reg.AwayClear(home); err != nil {
			s.log.Warn("could not forget a revoked home's absence", "err", err)
		}
		return
	}
	wait := time.Duration(cloudwire.UnreachableAfterMs) * time.Millisecond
	if why == cloudwire.ByeUpdate {
		wait = time.Duration(cloudwire.UpdateGraceMs) * time.Millisecond
	}
	s.log.Info("a box went away", "bye", why, "out_of_reach_after", wait)
	if !s.arm(home, wait, conn) {
		return
	}
	// Kept on disk, so a restart in the meantime neither forgets the alert
	// nor sends it twice.
	if err := s.reg.AwaySet(home, s.now().Add(wait)); err != nil {
		s.log.Warn("could not record a box's absence", "err", err)
	}
}

// arm starts the wait for box.unreachable, unless a newer connection than
// conn is already up. The home's generation moves, so a timer from an
// earlier absence cannot fire into this one.
func (s *Service) arm(home string, wait time.Duration, conn uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state(home)
	if conn < st.conn {
		return false
	}
	st.gen++
	st.online, st.told = false, false
	if st.stop != nil {
		st.stop()
	}
	gen := st.gen
	st.stop = s.after(wait, func() { s.unreachable(home, gen) })
	return true
}

// Resume starts the dead man's switch again after a restart. A home recorded
// as away waits only what was left of its wait, and one already told is not
// told again. A home with alert registrations and no record was connected
// when the service stopped; its box gets the whole wait to come back.
func (s *Service) Resume() error {
	away, err := s.reg.AwayAll()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	now := s.now()
	for _, a := range away {
		seen[a.Home] = true
		if s.Owns != nil && !s.Owns(a.Home) {
			continue
		}
		if a.Told {
			s.mu.Lock()
			st := s.state(a.Home)
			st.online, st.told = false, true
			s.mu.Unlock()
			continue
		}
		s.arm(a.Home, max(0, a.Due.Sub(now)), 0)
	}
	homes, err := s.reg.PushHomes(cloudwire.PushKindAlert)
	if err != nil {
		return err
	}
	wait := time.Duration(cloudwire.UnreachableAfterMs) * time.Millisecond
	for _, home := range homes {
		if seen[home] || (s.Owns != nil && !s.Owns(home)) {
			continue
		}
		if err := s.reg.AwaySet(home, now.Add(wait)); err != nil {
			return err
		}
		s.arm(home, wait, 0)
	}
	return nil
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
	if err := s.reg.AwayTold(home); err != nil {
		s.log.Warn("could not record box.unreachable as sent", "err", err)
	}
	s.log.Info("a box is out of reach; telling its phones")
	payload, err := cloudwire.AlertPayload(cloudwire.Alert{Home: home, Kind: protocol.PushBoxUnreachable})
	if err != nil {
		return
	}
	s.queueAlert(alertJob{home: home, payload: payload, expires: s.now().Add(unreachableExpiry)})
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

// regs is a home's registrations of a kind that may get a push now. A
// device an owner has suspended keeps its tokens, so lifting the suspension
// brings its pushes back, but gets nothing meanwhile. A watch's token waits
// for the watch app's topic.
func (s *Service) regs(home, kindName string) []registry.PushReg {
	regs, err := s.reg.PushRegs(home, kindName)
	if err != nil {
		s.log.Warn("could not read push registrations", "err", err)
		return nil
	}
	return slices.DeleteFunc(regs, func(r registry.PushReg) bool {
		return s.reg.Suspended(home, r.DeviceID, r.Epoch) || (r.App == cloudwire.PushAppWatch && s.WatchApp == "")
	})
}

// sendAlert posts an alert to the home's registered devices. What Apple or
// the network could not take goes again later, while the alert is worth
// showing; a gone token is forgotten.
func (s *Service) sendAlert(ctx context.Context, job alertJob) {
	if s.sender == nil {
		return
	}
	if job.tries == 0 {
		job.regs = s.regs(job.home, cloudwire.PushKindAlert)
		if len(job.regs) == 0 {
			return
		}
		if !s.allow(job.home, cloudwire.PushKindAlert) {
			pushCapped.Inc()
			s.log.Warn("a home passed its push cap; push dropped", "kind", cloudwire.PushKindAlert, "cap_per_hour", MaxAlertsPerHour)
			return
		}
	}
	job.tries++
	again := s.deliver(ctx, job.home, cloudwire.PushKindAlert, job.payload, job.expires, job.regs)
	if len(again) == 0 {
		return
	}
	wait := alertRetryAfter << (job.tries - 1)
	if job.tries >= alertTries || !s.now().Add(wait).Before(job.expires) {
		apnsResults[cloudwire.PushKindAlert]["failed"].Add(int64(len(again)))
		s.log.Warn("push: an alert could not reach Apple; given up", "devices", len(again), "tries", job.tries)
		return
	}
	job.regs = again
	s.retrying.Add(1)
	s.after(wait, func() {
		s.queueAlert(job)
		s.retrying.Add(-1)
	})
}

// sendWidgets posts a widgets push to the home's registered devices, once.
func (s *Service) sendWidgets(ctx context.Context, home string) {
	if s.sender == nil {
		return
	}
	regs := s.regs(home, KindWidgets)
	if len(regs) == 0 {
		return
	}
	if !s.allow(home, KindWidgets) {
		pushCapped.Inc()
		return
	}
	if again := s.deliver(ctx, home, KindWidgets, widgetsPayload, s.now().Add(widgetsExpiry), regs); len(again) > 0 {
		apnsResults[KindWidgets]["failed"].Add(int64(len(again)))
	}
}

// deliver posts one payload to each registration and returns those Apple
// or the network failed for now: an error, 429 or a 5xx.
func (s *Service) deliver(ctx context.Context, home, kindName string, payload []byte, exp time.Time, regs []registry.PushReg) []registry.PushReg {
	k := kinds[kindName]
	results := apnsResults[kindName]
	var again []registry.PushReg
	var sent, gone, failed int
	for _, r := range regs {
		// A watch and its phone get the same payload, so Apple shows one
		// alert when both are near; only the topic differs.
		app := ""
		if r.App == cloudwire.PushAppWatch {
			app = s.WatchApp
		}
		res, err := s.sender.Send(ctx, apns.Notification{Environment: r.Environment, DeviceToken: r.Token,
			App: app, Type: k.pushType, Payload: payload, Expiration: exp})
		switch {
		case err != nil || res.Status == http.StatusTooManyRequests || res.Status >= 500:
			failed++
			results["retry"].Inc()
			again = append(again, r)
		case res.OK():
			sent++
			results["ok"].Inc()
		case res.Gone:
			gone++
			results["gone"].Inc()
			if err := s.reg.PushGone(home, r.Token, kindName, res.GoneSince); err != nil {
				s.log.Warn("could not forget a gone token", "err", err)
			}
		default:
			failed++
			results["refused"].Inc()
			s.log.Warn("APNs refused a push", "kind", kindName, "status", res.Status, "reason", res.Reason)
		}
	}
	s.log.Debug("push sent", "kind", kindName, "devices", sent, "gone", gone, "failed", failed)
	return again
}

// sendQueued sends everything queued now, here, without the widget rate.
// Tests use it in place of the workers.
func (s *Service) sendQueued(ctx context.Context) {
	for {
		if job, ok := s.alerts.pop(); ok {
			s.sendAlert(ctx, job)
			continue
		}
		home, ok := s.widgets.pop()
		if !ok {
			return
		}
		s.mu.Lock()
		delete(s.widgetWaiting, home)
		s.mu.Unlock()
		s.sendWidgets(ctx, home)
	}
}
