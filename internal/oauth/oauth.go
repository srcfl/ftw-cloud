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
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

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
	// link that opens the FTW app, followed by the request id.
	AppLink = "https://app.ftw.energy/a/"
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
	// RefreshTTL caps a refresh token, and an agent's own end caps it
	// sooner.
	RefreshTTL = 30 * 24 * time.Hour
)

// Scopes. Each is a right the box grants an agent, by its registry name; a
// token carries those the client asked for and the box granted.
//
// The first five are in contract/registry.yaml today. The rest are the
// agent rights decided on 15 October 2026 and wait for their registry names
// (the core-agent-role contract); they move to protocol constants when it
// lands.
const (
	ScopeLiveRead     = protocol.ScopeLiveRead
	ScopePlanRead     = protocol.ScopePlanRead
	ScopeHistoryRead  = protocol.ScopeHistoryRead
	ScopeHealthRead   = protocol.ScopeHealthRead
	ScopeEventsRead   = protocol.ScopeEventsRead
	ScopeLogsRead     = "ftw.logs.read"
	ScopeConfigRead   = "ftw.config.read"
	ScopeDiagRun      = "ftw.diag.run"
	ScopeDispatchHold = "ftw.dispatch.hold"
	ScopeGoalsRequest = "ftw.goals.request"
)

// ReadScopes are what an agent gets by default.
var ReadScopes = []string{ScopeLiveRead, ScopePlanRead, ScopeHistoryRead, ScopeHealthRead, ScopeEventsRead,
	ScopeLogsRead, ScopeConfigRead, ScopeDiagRun}

// ControlScopes need the owner to tick control.
var ControlScopes = []string{ScopeDispatchHold, ScopeGoalsRequest}

// AllScopes is every scope a client may ask for.
var AllScopes = append(slices.Clone(ReadScopes), ControlScopes...)

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
	ScopeDiagRun:      "Run checks that change nothing",
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
}

// Server is the authorization server.
type Server struct {
	st    *store
	keys  AgentKeys
	fetch *fetcher
	log   *slog.Logger
	now   func() time.Time
	hub   hub

	authorizeLimit, registerLimit, lookupLimit limiter

	roster chan rosterEvent

	// Shard names the shard a home lives on (shard.Directory). Nil is one
	// shard, "".
	Shard func(home string) string
	// AgentExpiry reads when the box ends an agent, from its roster entry.
	// Nil, or a zero time, is no end the service knows of; the box still
	// enforces its own.
	AgentExpiry func(d cloudwire.Device) time.Time
	// OnRevoke hears that an agent is gone: its owner revoked it, or it
	// ran out. The MCP server drops its warm session. It must not block.
	OnRevoke func(home, agent string)
}

// New opens the authorization server's state at path.
func New(path string, keys AgentKeys, log *slog.Logger) (*Server, error) {
	return newServer(path, keys, log, nil)
}

func newServer(path string, keys AgentKeys, log *slog.Logger, roots *x509.CertPool) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	st, err := openStore(path)
	if err != nil {
		return nil, err
	}
	s := &Server{st: st, keys: keys, fetch: newFetcher(roots), log: log, now: time.Now, hub: hub{subs: map[string]map[chan struct{}]struct{}{}},
		authorizeLimit: newLimiter(30, 1), registerLimit: newLimiter(20, 0.2), lookupLimit: newLimiter(20, 5),
		roster: make(chan rosterEvent, 1024)}
	return s, nil
}

// Close closes the state.
func (s *Server) Close() error { return s.st.close() }

// Routes are the paths the authorization server answers, for the server's
// list.
var Routes = []string{
	"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource",
	"/.well-known/oauth-protected-resource/mcp", "/oauth/authorize", "/oauth/token", "/oauth/register",
	"/oauth/revoke", "/oauth/requests",
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
	mux.HandleFunc("GET /oauth/requests", s.serveRequestByCode)
	mux.HandleFunc("GET /oauth/requests/{rid}", s.serveRequest)
	mux.HandleFunc("GET /oauth/requests/{rid}/events", s.serveEvents)
	mux.HandleFunc("POST /oauth/requests/{rid}/deny", s.serveDeny)
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

type rosterEvent struct {
	home    string
	devices []cloudwire.Device
	// tries counts how often the event came back because the keys part
	// could not keep an approved key.
	tries int
}

// keepRetry is how long an approval waits before it tries the keys part
// again, and keepTries how often. A box sends its roster when it changes,
// so the approval cannot wait for the next one.
var (
	keepRetry = 5 * time.Second
	keepTries = 24
)

// Roster hears each roster the service keeps. A device whose key a pending
// consent made is that consent's approval; an agent the roster no longer
// lists is revoked. The work happens on Run's goroutine, in order, since
// this runs on the box's.
func (s *Server) Roster(home string, r *cloudwire.Roster) {
	ev := rosterEvent{home: home, devices: slices.Clone(r.Devices)}
	select {
	case s.roster <- ev:
	default:
		// The next roster carries the same devices.
		s.log.Warn("roster queue full; an agent change waits for the next roster")
	}
}

// Run applies rosters and sweeps until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.roster:
			s.applyRoster(ctx, ev)
		case <-t.C:
			s.sweep(ctx)
		}
	}
}

func (s *Server) applyRoster(ctx context.Context, ev rosterEvent) {
	now := s.now()
	retry := false
	listed := map[string]cloudwire.Device{}
	for _, d := range ev.devices {
		if d.Tun {
			listed[d.ID] = d
		}
	}
	// Approvals: a pending consent's key in the box's signed roster.
	for _, d := range listed {
		ridHash, c, ok, err := s.st.pendingByKey(d.Key, now)
		if err != nil || !ok {
			continue
		}
		if cloudwire.DeviceID(d.Key) != d.ID {
			continue
		}
		if err := s.keys.Keep(ctx, c.Kid); err != nil {
			s.log.Warn("an approved agent's key could not be kept; trying again", "err", err)
			retry = true
			continue
		}
		c.Home, c.Agent, c.Shard = ev.home, d.ID, s.shard(ev.home)
		c.Granted = strings.Join(intersect(splitScope(c.Scope), d.Scopes), " ")
		if err := s.st.approve(ridHash, c, s.expiry(d), now); err != nil {
			continue
		}
		s.hub.notify(string(ridHash))
	}
	if retry && ev.tries < keepTries {
		ev.tries++
		time.AfterFunc(keepRetry, func() {
			select {
			case s.roster <- ev:
			default:
			}
		})
	}
	// Revocations: an agent the roster no longer lists, or lists with
	// another key.
	agents, err := s.st.agentsOf(ev.home)
	if err != nil {
		return
	}
	for _, a := range agents {
		if d, ok := listed[a.Agent]; ok && string(d.Key) == string(a.Key) {
			continue
		}
		s.revoke(ctx, a)
	}
}

func (s *Server) revoke(ctx context.Context, a agentRow) {
	if err := s.st.dropAgent(a.Home, a.Agent); err != nil {
		s.log.Warn("could not drop an agent", "err", err)
		return
	}
	if err := s.keys.Forget(ctx, a.Kid); err != nil {
		s.log.Warn("the keys part could not forget an agent's key", "err", err)
	}
	if s.OnRevoke != nil {
		s.OnRevoke(a.Home, a.Agent)
	}
}

func (s *Server) sweep(ctx context.Context) {
	now := s.now()
	kids, err := s.st.sweep(now)
	if err != nil {
		s.log.Warn("oauth upkeep failed", "err", err)
	}
	for _, kid := range kids {
		_ = s.keys.Forget(ctx, kid)
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

func (s *Server) expiry(d cloudwire.Device) time.Time {
	if s.AgentExpiry == nil {
		return time.Time{}
	}
	return s.AgentExpiry(d)
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
