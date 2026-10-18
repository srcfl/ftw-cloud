// Package oauth is FTW Cloud's authorization server for assistants: ChatGPT,
// Claude, Grok and any MCP client. It follows the MCP authorization spec,
// revision 2026-07-28: OAuth 2.1 with PKCE S256 only, authorization server
// metadata (RFC 8414) with iss in every authorization response (RFC 9207),
// protected resource metadata for /mcp (RFC 9728), audience-bound tokens by
// the resource parameter (RFC 8707), client ID metadata documents, and
// dynamic registration (RFC 7591) kept for clients that need it.
//
// There is no account and no password. The authorize page shows a short
// code, a QR and a link to the FTW app. The owner approves in the app or on
// the box's own page, and the box lists the new agent's key in the roster it
// signs. When that roster arrives, the page, which waits on a server-sent
// event, sends the browser back to the client with a code.
//
// A token is bound to one agent of one home: (shard, home, agent id). It
// never leaves the service. The box sees the agent's own Noise session,
// opened by the keys part, and decides what each request may do.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Addresses.
const (
	// Issuer is the authorization server's identifier, and the origin of
	// every endpoint.
	Issuer = "https://cloud.ftw.energy"
	// Resource is the MCP server's canonical URI: every token's audience.
	Resource = Issuer + "/mcp"
	// AppLink is where the QR and the button send the owner: a universal
	// link that opens the FTW app. Its fragment carries the request id and
	// the signed offer, so neither reaches a server's log.
	AppLink = "https://app.ftw.energy/a"
	// AppOrigin may read a request's details from a browser.
	AppOrigin = "https://app.ftw.energy"
)

// Lifetimes.
const (
	// RequestTTL is how long a consent waits for the owner.
	RequestTTL = 10 * time.Minute
	// CodeTTL is how long an authorization code lasts.
	CodeTTL = time.Minute
	// AccessTTL is an access token's life. Short: a token that leaks is
	// worth little, and a revoked agent loses access at its box anyway.
	AccessTTL = 10 * time.Minute
	// RefreshTTL is a refresh token's life: the longest grant an agent may
	// have. The agent's end does not shorten it, so a grant the owner renews
	// while its client is idle keeps its tokens; an agent past its end is
	// refused at every refresh and swept.
	RefreshTTL = maxGrant
	// maxGrant is the longest end the service takes from a roster.
	maxGrant = time.Duration(protocol.AgentMaxMs) * time.Millisecond
)

// Scopes. Each is a right the box grants an agent, by its registry name
// (docs/agents.md in srcfl/ftw); a token carries those the client asked for
// and the box granted.
const (
	ScopeLiveRead     = protocol.ScopeLiveRead
	ScopePlanRead     = protocol.ScopePlanRead
	ScopeHistoryRead  = protocol.ScopeHistoryRead
	ScopeHealthRead   = protocol.ScopeHealthRead
	ScopeEventsRead   = protocol.ScopeEventsRead
	ScopeLogsRead     = protocol.ScopeLogsRead
	ScopeConfigRead   = protocol.ScopeConfigRead
	ScopeDiagRun      = protocol.ScopeDiagRun
	ScopeSetupWrite   = protocol.ScopeSetupWrite
	ScopeDispatchHold = protocol.ScopeDispatchHold
	ScopeGoalsRequest = protocol.ScopeGoalsRequest
)

// ReadScopes are what an agent gets by default.
var ReadScopes = []string{ScopeLiveRead, ScopePlanRead, ScopeHistoryRead, ScopeHealthRead, ScopeEventsRead,
	ScopeLogsRead, ScopeConfigRead, ScopeDiagRun}

// ControlScopes need the owner to tick control.
var ControlScopes = []string{ScopeDispatchHold, ScopeGoalsRequest}

// AllScopes is every scope a client may ask for.
var AllScopes = append(append(slices.Clone(ReadScopes), ControlScopes...), ScopeSetupWrite)

// scopeWords says what each scope lets an assistant do, for the consent
// page.
var scopeWords = map[string]string{
	ScopeLiveRead:     "See power, battery and the car right now",
	ScopePlanRead:     "See the plan and why it looks that way",
	ScopeHistoryRead:  "See past readings",
	ScopeHealthRead:   "See how the box and its devices are doing",
	ScopeEventsRead:   "See alerts and events",
	ScopeLogsRead:     "Read the box's logs, with secrets removed",
	ScopeConfigRead:   "Read the settings, with secrets removed",
	ScopeDiagRun:      "Read full technical diagnostics, source, logs and backups; backups can contain saved credentials",
	ScopeSetupWrite:   "Save the exact setup draft you confirm, including equipment and electrical limits, and restart to apply it when you confirm",
	ScopeDispatchHold: "Hold the battery or charge the car for a short, capped time",
	ScopeGoalsRequest: "Ask for changes to goals and schedules, which wait for your yes",
}

// Client authentication methods and grants.
const (
	authNone        = "none"
	authSecretPost  = "client_secret_post"
	authSecretBasic = "client_secret_basic"
	grantCode       = "authorization_code"
	grantRefresh    = "refresh_token"
)

// AgentKeys is the keys part, as the authorization server uses it.
type AgentKeys interface {
	New(ctx context.Context) (kid string, pub []byte, err error)
	Keep(ctx context.Context, kid string) error
	Forget(ctx context.Context, kid string) error
	// SignOffer signs an offer for key kid, which must still be pending.
	SignOffer(ctx context.Context, kid string, offer []byte) ([]byte, error)
	OfferKey(ctx context.Context) ([]byte, error)
}

// Server is the authorization server.
type Server struct {
	st    *store
	keys  AgentKeys
	fetch *fetcher
	log   *slog.Logger
	now   func() time.Time
	hub   hub
	route routeKey

	// Each endpoint a stranger can call has a bucket for everyone and one
	// per address.
	authorizeLimit, registerLimit, lookupLimit limiter
	authorizeByIP, registerByIP, lookupByIP    *ipLimiter
	streams                                    streams

	// The newest roster, or purge, per home, not applied yet; and homes
	// whose approval waits for the keys part.
	pmu     sync.Mutex
	pending map[string]*homeEvent
	retries map[string]*approvalRetry
	wake    chan struct{}
	busy    atomic.Int32

	offerKey offerKey

	// Shard names the shard a home lives on (shard.Directory). Nil is one
	// shard, "".
	Shard func(home string) string
	// OnRevoke hears that an agent is gone: its owner revoked it, or it
	// ran out. The MCP server drops its warm session. It must not block.
	OnRevoke func(home, agent string)
	// ClaimInvite proves a pending key to the box through its invitation door.
	ClaimInvite                          func(context.Context, InviteClaim) error
	Invitation                           func(home string, hash, box []byte) (time.Time, bool)
	aliases                              inviteAliases
	invitePublishLimit, inviteClaimLimit limiter
	invitePublishByIP, inviteClaimByIP   *ipLimiter
}

// New opens the authorization server's state at path.
func New(path string, keys AgentKeys, log *slog.Logger) (*Server, error) {
	return newServer(path, keys, log, nil)
}

func newServer(path string, keys AgentKeys, log *slog.Logger, roots *x509.CertPool) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	route, err := loadRouteKey(filepath.Join(filepath.Dir(path), "oauth-route.key"))
	if err != nil {
		return nil, err
	}
	st, err := openStore(path)
	if err != nil {
		return nil, err
	}
	s := &Server{st: st, keys: keys, fetch: newFetcher(roots), log: log, now: time.Now, route: route,
		hub:            hub{subs: map[string]map[chan struct{}]struct{}{}},
		authorizeLimit: newLimiter(30, 1), registerLimit: newLimiter(20, 0.2), lookupLimit: newLimiter(20, 5),
		authorizeByIP: newIPLimiter(10, 0.2), registerByIP: newIPLimiter(5, 1.0/60), lookupByIP: newIPLimiter(10, 1),
		streams: streams{per: map[string]int{}},
		pending: map[string]*homeEvent{}, retries: map[string]*approvalRetry{}, wake: make(chan struct{}, 1)}
	s.invitePublishLimit, s.inviteClaimLimit = newLimiter(20, 1), newLimiter(20, 0.2)
	s.invitePublishByIP, s.inviteClaimByIP = newIPLimiter(5, 1.0/60), newIPLimiter(5, 1.0/60)
	return s, nil
}

// Close closes the state.
func (s *Server) Close() error { return s.st.close() }

// Routes are the paths the authorization server answers, for the server's
// list.
var Routes = []string{
	"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
	"/.well-known/oauth-protected-resource/mcp", "/oauth/authorize", "/oauth/token", "/oauth/register",
	"/oauth/revoke", "/oauth/requests", "/oauth/invitations", "/.well-known/ftw-offer-key",
}

// Mount adds the authorization server's routes to mux.
func (s *Server) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.serveMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.serveResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.serveResourceMetadata)
	mux.HandleFunc("GET /oauth/authorize", s.serveAuthorize)
	mux.HandleFunc("POST /oauth/token", s.serveToken)
	mux.HandleFunc("POST /oauth/register", s.serveRegister)
	mux.HandleFunc("POST /oauth/revoke", s.serveRevoke)
	mux.HandleFunc("GET /.well-known/ftw-offer-key", s.serveOfferKey)
	mux.HandleFunc("GET /oauth/requests", s.serveRequestByCode)
	mux.HandleFunc("GET /oauth/requests/{rid}", s.serveRequest)
	mux.HandleFunc("GET /oauth/requests/{rid}/connect", s.serveConnect)
	mux.HandleFunc("POST /oauth/requests/{rid}/mode", s.serveMode)
	mux.HandleFunc("GET /oauth/requests/{rid}/events", s.serveEvents)
	mux.HandleFunc("POST /oauth/requests/{rid}/deny", s.serveDeny)
	mux.HandleFunc("POST /oauth/requests/{rid}/invite", s.serveInvite)
	mux.HandleFunc("POST /oauth/invitations", s.servePublishInvitation)
	mux.HandleFunc("OPTIONS /oauth/invitations", s.servePublishInvitation)
}

// --------------------------------------------------------------------------
// Metadata
// --------------------------------------------------------------------------

// ResourceMetadataURL is where /mcp's protected resource metadata lives,
// named in every challenge.
const ResourceMetadataURL = Issuer + "/.well-known/oauth-protected-resource/mcp"

func (s *Server) serveMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         Issuer,
		"authorization_endpoint":                         Issuer + "/oauth/authorize",
		"token_endpoint":                                 Issuer + "/oauth/token",
		"registration_endpoint":                          Issuer + "/oauth/register",
		"revocation_endpoint":                            Issuer + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{grantCode, grantRefresh},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{authNone, authSecretPost, authSecretBasic},
		"revocation_endpoint_auth_methods_supported":     []string{authNone, authSecretPost, authSecretBasic},
		"scopes_supported":                               AllScopes,
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          "https://github.com/srcfl/ftw-cloud/blob/main/README.md",
	}, true)
}

func (s *Server) serveResourceMetadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 Resource,
		"authorization_servers":    []string{Issuer},
		"scopes_supported":         ReadScopes,
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "FTW Cloud",
		"resource_documentation":   "https://github.com/srcfl/ftw-cloud/blob/main/README.md",
	}, true)
}

// --------------------------------------------------------------------------
// The box's roster
// --------------------------------------------------------------------------

// homeEvent is what waits to be applied for one home: the newest roster
// only, and whether the home was purged first. A newer roster replaces an
// older one, so nothing old is ever applied and nothing is dropped.
type homeEvent struct {
	purge   bool
	devices []cloudwire.Device
	roster  bool
}

// approvalRetry is a home whose approval the keys part could not take yet.
// A retry runs the approval pass alone, on the newest roster.
type approvalRetry struct {
	devices []cloudwire.Device
	tries   int
	at      time.Time
}

// keepRetry is how long an approval waits before it tries the keys part
// again, and keepTries how often. A box sends its roster when it changes,
// so the approval cannot wait for the next one. keysTimeout bounds one call
// to the keys part.
var (
	keepRetry   = 5 * time.Second
	keepTries   = 24
	keysTimeout = 5 * time.Second
)

// Roster hears each roster the service keeps. A device whose key a pending
// consent made is that consent's approval; an agent the roster no longer
// lists is revoked. The work happens on Run's goroutine, since this runs on
// the box's.
func (s *Server) Roster(home string, r *cloudwire.Roster) {
	s.pmu.Lock()
	ev := s.pending[home]
	if ev == nil {
		ev = &homeEvent{}
		s.pending[home] = ev
	}
	ev.devices, ev.roster = slices.Clone(r.Devices), true
	s.pmu.Unlock()
	s.poke()
}

// DropHome forgets a home its box purged: its agents, their tokens and keys,
// and its consents. A roster that came before it is not applied.
func (s *Server) DropHome(home string) {
	s.pmu.Lock()
	s.pending[home] = &homeEvent{purge: true}
	delete(s.retries, home)
	s.pmu.Unlock()
	s.poke()
}

func (s *Server) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run applies rosters, retries approvals and forgets, and sweeps, until
// ctx ends. It first forgets the keys whose agents went while the keys part
// was away.
func (s *Server) Run(ctx context.Context) {
	s.forgetPending(ctx)
	sweep := time.NewTicker(time.Minute)
	defer sweep.Stop()
	retry := time.NewTicker(min(keepRetry, time.Second))
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			s.applyPending(ctx)
		case <-retry.C:
			s.retryApprovals(ctx)
		case <-sweep.C:
			s.sweep(ctx)
			s.forgetPending(ctx)
		}
	}
}

func (s *Server) applyPending(ctx context.Context) {
	s.busy.Add(1)
	defer s.busy.Add(-1)
	s.pmu.Lock()
	evs := s.pending
	s.pending = map[string]*homeEvent{}
	s.pmu.Unlock()
	for home, ev := range evs {
		if ev.purge {
			s.dropHome(ctx, home)
		}
		if ev.roster {
			s.applyRoster(ctx, home, ev.devices)
		}
	}
}

// listedAgents are the rows this service serves: a personal agent's, with
// its grant and an end still ahead, by its full key. Support and release
// rows reach their homes another way.
func (s *Server) listedAgents(devices []cloudwire.Device) map[string]cloudwire.Device {
	now := s.now()
	listed := map[string]cloudwire.Device{}
	for _, d := range devices {
		// An agent row has no tunnel of its own (tun is false): only the
		// keys part opens its session.
		if d.Agent != nil && d.Role == protocol.RoleAgent && len(d.Key) == 32 && cloudwire.DeviceID(d.Key) == d.ID &&
			now.Before(time.UnixMilli(d.Agent.ExpiresAtMs)) {
			listed[string(d.Key)] = d
		}
	}
	return listed
}

func (s *Server) applyRoster(ctx context.Context, home string, devices []cloudwire.Device) {
	listed := s.listedAgents(devices)
	// A key belongs to one home. A roster that lists, as its agent, a key
	// approved for another home has a copy it should not: the agent goes
	// everywhere, and its key with it.
	for key := range listed {
		if a, ok, err := s.st.agentByKey([]byte(key)); err == nil && ok && a.Home != home {
			s.log.Warn("a roster listed an agent approved for another home; revoking it")
			s.revoke(ctx, a)
			delete(listed, key)
		}
	}
	if s.approve(ctx, home, listed) {
		s.pmu.Lock()
		r := s.retries[home]
		if r == nil {
			r = &approvalRetry{}
			s.retries[home] = r
		}
		r.devices, r.at = devices, time.Now().Add(keepRetry)
		s.pmu.Unlock()
	} else {
		s.pmu.Lock()
		delete(s.retries, home)
		s.pmu.Unlock()
	}
	// Every agent the roster lists keeps the grant the box gives it now:
	// an owner may widen, narrow or renew it. One it no longer lists, or
	// lists under another id, is revoked.
	agents, err := s.st.agentsOf(home)
	if err != nil {
		return
	}
	for _, a := range agents {
		d, ok := listed[string(a.Key)]
		if !ok || d.ID != a.Agent {
			s.revoke(ctx, a)
			continue
		}
		if err := s.st.setGrant(a.Home, a.Agent, grantOf(d, s.now())); err != nil {
			s.log.Warn("could not update an agent's grant", "err", err)
		}
	}
}

// approve is the approval pass: a pending consent's key in the box's signed
// roster, for the client the offer named. It reports whether an approval
// waits for the keys part.
func (s *Server) approve(ctx context.Context, home string, listed map[string]cloudwire.Device) (retry bool) {
	now := s.now()
	for _, d := range listed {
		ridHash, c, ok, err := s.st.pendingByKey(d.Key, now)
		if err != nil || !ok || d.Agent.Principal.ClientID != c.ClientID {
			continue
		}
		kctx, cancel := context.WithTimeout(ctx, keysTimeout)
		err = s.keys.Keep(kctx, c.Kid)
		cancel()
		if err != nil {
			s.log.Warn("an approved agent's key could not be kept; trying again", "err", err)
			retry = true
			continue
		}
		c.Home, c.Agent, c.Shard = home, d.ID, s.shard(home)
		c.Granted = strings.Join(intersect(splitScope(c.Scope), d.Agent.Scopes), " ")
		if err := s.st.approve(ridHash, c, grantOf(d, now), now); err != nil {
			s.log.Warn("could not record an approval", "err", err)
			retry = true
			continue
		}
		s.hub.notify(string(ridHash))
	}
	return retry
}

// retryApprovals runs the approval pass again for homes that wait on the
// keys part, on each home's newest roster. It revokes nothing: that is the
// roster's own pass, which already ran.
func (s *Server) retryApprovals(ctx context.Context) {
	now := time.Now()
	s.pmu.Lock()
	due := map[string][]cloudwire.Device{}
	for home, r := range s.retries {
		if !now.Before(r.at) {
			due[home] = r.devices
		}
	}
	s.pmu.Unlock()
	for home, devices := range due {
		retry := s.approve(ctx, home, s.listedAgents(devices))
		s.pmu.Lock()
		if r := s.retries[home]; r != nil {
			r.tries++
			if !retry || r.tries >= keepTries {
				delete(s.retries, home)
			} else {
				r.at = now.Add(keepRetry)
			}
		}
		s.pmu.Unlock()
	}
}

// grantOf is an agent row's grant, as the box signed it in the roster.
// The service never takes an end past the longest grant from now, whatever a
// roster says.
func grantOf(d cloudwire.Device, now time.Time) agentGrant {
	end := time.UnixMilli(d.Agent.ExpiresAtMs)
	if most := now.Add(maxGrant); end.After(most) {
		end = most
	}
	return agentGrant{Scopes: slices.Clone(d.Agent.Scopes), Ops: slices.Clone(d.Agent.Ops), Caps: d.Agent.Caps,
		Expires: end}
}

// revoke drops an agent and its tokens, and has its key forgotten.
func (s *Server) revoke(ctx context.Context, a agentRow) {
	if err := s.st.dropAgent(a.Home, a.Agent, a.Kid); err != nil {
		s.log.Warn("could not drop an agent", "err", err)
		return
	}
	s.forget(ctx, a.Kid)
	if s.OnRevoke != nil {
		s.OnRevoke(a.Home, a.Agent)
	}
}

// dropHome revokes every agent of a purged home and deletes its consents.
func (s *Server) dropHome(ctx context.Context, home string) {
	agents, err := s.st.agentsOf(home)
	if err != nil {
		s.log.Warn("could not read a purged home's agents", "err", err)
		return
	}
	for _, a := range agents {
		s.revoke(ctx, a)
	}
	if err := s.st.dropRequests(home); err != nil {
		s.log.Warn("could not delete a purged home's consents", "err", err)
	}
}

// forget asks the keys part to delete a key the store already queued for
// forgetting, and dequeues it once done. A key the keys part could not
// forget now is tried again every minute and at the next start.
func (s *Server) forget(ctx context.Context, kid string) {
	kctx, cancel := context.WithTimeout(ctx, keysTimeout)
	defer cancel()
	if err := s.keys.Forget(kctx, kid); err != nil && !errors.Is(err, keys.ErrUnknownKey) {
		s.log.Warn("the keys part could not forget a key; trying again later", "err", err)
		return
	}
	_ = s.st.forgotten(kid)
}

func (s *Server) forgetPending(ctx context.Context) {
	kids, err := s.st.toForget()
	if err != nil {
		return
	}
	for _, kid := range kids {
		s.forget(ctx, kid)
	}
}

func (s *Server) sweep(ctx context.Context) {
	now := s.now()
	s.pruneInvitationAliases(now)
	if err := s.st.sweep(now); err != nil {
		s.log.Warn("oauth upkeep failed", "err", err)
	}
	gone, err := s.st.expiredAgents(now)
	if err == nil {
		for _, a := range gone {
			s.revoke(ctx, a)
		}
	}
}

func (s *Server) shard(home string) string {
	if s.Shard == nil {
		return ""
	}
	return s.Shard(home)
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// hub wakes the event streams waiting on a consent.
type hub struct {
	mu   sync.Mutex
	subs map[string]map[chan struct{}]struct{}
}

func (h *hub) subscribe(ridHash string) (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	if h.subs[ridHash] == nil {
		h.subs[ridHash] = map[chan struct{}]struct{}{}
	}
	h.subs[ridHash][ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs[ridHash], ch)
		if len(h.subs[ridHash]) == 0 {
			delete(h.subs, ridHash)
		}
		h.mu.Unlock()
	}
}

func (h *hub) notify(ridHash string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs[ridHash] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// limiter is a token bucket shared by every caller of one endpoint. It
// bounds what strangers can make the service do; it names nobody.
type limiter struct {
	mu            sync.Mutex
	tokens, burst float64
	rate          float64
	at            time.Time
}

func newLimiter(burst, perSecond float64) limiter {
	return limiter{tokens: burst, burst: burst, rate: perSecond}
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.at.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.at).Seconds()*l.rate)
	}
	l.at = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// ipLimiter is a token bucket per address, an IPv6 address by its /64, so
// one caller cannot spend everyone's bucket. A full bucket carries nothing,
// so it is the first to go when the table fills.
type ipLimiter struct {
	mu          sync.Mutex
	burst, rate float64
	m           map[netip.Prefix]*limiter
}

// maxAddresses bounds the per-address table.
const maxAddresses = 50_000

func newIPLimiter(burst, perSecond float64) *ipLimiter {
	return &ipLimiter{burst: burst, rate: perSecond, m: map[netip.Prefix]*limiter{}}
}

func (l *ipLimiter) allow(r *http.Request, now time.Time) bool {
	key, ok := clientPrefix(r)
	if !ok {
		return false
	}
	l.mu.Lock()
	b := l.m[key]
	if b == nil {
		if len(l.m) >= maxAddresses {
			for k, v := range l.m {
				if v.tokens+now.Sub(v.at).Seconds()*v.rate >= v.burst {
					delete(l.m, k)
				}
			}
			if len(l.m) >= maxAddresses {
				l.mu.Unlock()
				return false
			}
		}
		nl := newLimiter(l.burst, l.rate)
		b = &nl
		l.m[key] = b
	}
	l.mu.Unlock()
	return b.allow(now)
}

// clientPrefix is the caller's address as a bucket's key. TLS ends in this
// process, so RemoteAddr is the caller's own.
func clientPrefix(r *http.Request) (netip.Prefix, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	return p, err == nil
}

// limited takes one token from both of an endpoint's buckets.
func (s *Server) limited(global *limiter, byIP *ipLimiter, r *http.Request) bool {
	now := s.now()
	return !byIP.allow(r, now) || !global.allow(now)
}

// streams bounds the consent pages' event streams: a few per request, and
// a total.
type streams struct {
	mu    sync.Mutex
	per   map[string]int
	total int
}

const (
	maxStreamsPerRequest = 2
	maxStreams           = 4096
)

func (st *streams) open(rid string) (func(), bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.per[rid] >= maxStreamsPerRequest || st.total >= maxStreams {
		return nil, false
	}
	st.per[rid]++
	st.total++
	return func() {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.total--
		if st.per[rid]--; st.per[rid] <= 0 {
			delete(st.per, rid)
		}
	}, true
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any, cache bool) {
	w.Header().Set("Content-Type", "application/json")
	if cache {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) && !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}
