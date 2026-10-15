package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Token prefixes, so a leaked token is recognisable for what it is. After
// the prefix comes the token's route, then a dot and the secret. The route
// is the home, sealed with a fresh nonce under the service's route key: any
// instance can tell which shard holds a token's home without a lookup, and
// a client sees no id that is the same in two of its tokens, so it cannot
// link one connection to another by it.
const (
	accessPrefix  = "ftwat_"
	refreshPrefix = "ftwrt_"
)

// routeKey seals a home into a token's route. Every instance that routes
// tokens holds the same one.
type routeKey struct{ aead cipher.AEAD }

// loadRouteKey reads the route key, making it on first start.
func loadRouteKey(path string) (routeKey, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return routeKey{}, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return routeKey{}, err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			return routeKey{}, err
		}
		if err := f.Close(); err != nil {
			return routeKey{}, err
		}
	} else if err != nil {
		return routeKey{}, err
	}
	if len(key) != 32 {
		return routeKey{}, fmt.Errorf("oauth: %s holds %d bytes, want 32", path, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return routeKey{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return routeKey{}, err
	}
	return routeKey{aead: aead}, nil
}

// newToken is prefix, the home sealed with a fresh nonce, a dot and 32
// random bytes.
func (k routeKey) newToken(prefix, home string) string {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	route := k.aead.Seal(nonce, nonce, []byte(home), []byte(prefix))
	return prefix + base64.RawURLEncoding.EncodeToString(route) + "." + randomToken(32)
}

// home opens a token's route.
func (k routeKey) home(tok string) (string, bool) {
	for _, p := range []string{accessPrefix, refreshPrefix} {
		if !tokenShape(tok, p) {
			continue
		}
		route, _, _ := strings.Cut(strings.TrimPrefix(tok, p), ".")
		raw, err := base64.RawURLEncoding.DecodeString(route)
		n := k.aead.NonceSize()
		if err != nil || len(raw) < n+k.aead.Overhead() {
			return "", false
		}
		home, err := k.aead.Open(nil, raw[:n], raw[n:], []byte(p))
		if err != nil {
			return "", false
		}
		return string(home), true
	}
	return "", false
}

// tokenShape is a token as this server makes one: the prefix, a route of
// base64url, a dot and 43 characters of base64url. Anything else is refused
// before the store is asked.
func tokenShape(tok, prefix string) bool {
	rest, ok := strings.CutPrefix(tok, prefix)
	if !ok {
		return false
	}
	route, secret, ok := strings.Cut(rest, ".")
	if !ok || len(route) < 40 || len(route) > 160 || len(secret) != 43 {
		return false
	}
	return base64URL(route) && base64URL(secret)
}

func base64URL(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// TokenHome is the home a token is routed to, for a router that sends it to
// the home's shard. It proves nothing: only the stored hash does.
func (s *Server) TokenHome(tok string) (string, bool) { return s.route.home(tok) }

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
	readDeadline(w)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
		return
	}
	for k, v := range r.PostForm {
		if len(v) > 1 {
			tokenError(w, http.StatusBadRequest, "invalid_request", k+" appears more than once")
			return
		}
	}
	c, ok := s.authenticateClient(r)
	if !ok {
		if _, _, basic := r.BasicAuth(); basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="FTW Cloud"`)
		}
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	if res := r.PostForm.Get("resource"); res != "" && !sameResource(res) {
		tokenError(w, http.StatusBadRequest, "invalid_target", "this server issues tokens only for "+Resource)
		return
	}
	switch r.PostForm.Get("grant_type") {
	case grantCode:
		s.exchangeCode(w, r, c)
	case grantRefresh:
		s.refresh(w, r, c)
	default:
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code or refresh_token")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, cl client) {
	f := r.PostForm
	verifier := f.Get("code_verifier")
	if !verifierRE.MatchString(verifier) {
		tokenError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required")
		return
	}
	c, ridHash, reused, err := s.st.redeem(f.Get("code"), s.now())
	if reused {
		// The code was used before: whoever holds the first tokens may not
		// be the client. They go.
		_ = s.st.revokeFamily(ridHash)
	}
	if err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is not valid")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	// A redirect_uri the authorize request named must be named again, the
	// same; one it left out may be named only as the one it used.
	redirect := f.Get("redirect_uri")
	if c.ClientID != cl.ID || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.Challenge)) != 1 ||
		(c.RedirectGiven || redirect != "") && redirect != c.RedirectURI {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the code is not valid")
		return
	}
	a, ok, err := s.st.agent(c.Home, c.Agent)
	if err != nil || !ok || s.agentGone(a) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the owner removed this assistant")
		return
	}
	s.issue(w, ridHash, cl.ID, a, c.Granted, s.now().Add(RefreshTTL))
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, cl client) {
	tok := r.PostForm.Get("refresh_token")
	t, ok, err := s.st.token(tok)
	if err != nil || !ok || t.Kind != kindRefresh || t.ClientID != cl.ID || !s.now().Before(t.Expires) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the refresh token is not valid")
		return
	}
	fresh, err := s.st.rotate(tok, s.now())
	if err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "could not refresh")
		return
	}
	if !fresh {
		// A refresh token used twice: one of the two holders stole it.
		_ = s.st.revokeFamily(t.Family)
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the refresh token was used before")
		return
	}
	scope := t.Scope
	if asked := splitScope(r.PostForm.Get("scope")); len(asked) > 0 {
		have := splitScope(t.Scope)
		for _, sc := range asked {
			if !slices.Contains(have, sc) {
				tokenError(w, http.StatusBadRequest, "invalid_scope", "a refresh cannot widen the scope")
				return
			}
		}
		scope = strings.Join(asked, " ")
	}
	a, ok, err := s.st.agent(t.Home, t.Agent)
	if err != nil || !ok || s.agentGone(a) {
		tokenError(w, http.StatusBadRequest, "invalid_grant", "the owner removed this assistant")
		return
	}
	s.issue(w, t.Family, cl.ID, a, scope, t.Expires)
}

// issue writes a new access token and a new refresh token of one family.
// The refresh token ends no later than refreshEnd or the agent.
func (s *Server) issue(w http.ResponseWriter, family []byte, clientID string, a agentRow, scope string, refreshEnd time.Time) {
	now := s.now()
	if a.Expires.Before(refreshEnd) {
		refreshEnd = a.Expires
	}
	accessEnd := now.Add(AccessTTL)
	if accessEnd.After(refreshEnd) {
		accessEnd = refreshEnd
	}
	access, refresh := s.route.newToken(accessPrefix, a.Home), s.route.newToken(refreshPrefix, a.Home)
	base := tokenRow{Family: family, ClientID: clientID, Home: a.Home, Agent: a.Agent, Scope: scope, Resource: Resource}
	at, rt := base, base
	at.Kind, at.Expires = kindAccess, accessEnd
	rt.Kind, rt.Expires = kindRefresh, refreshEnd
	if err := s.st.putToken(access, at); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "could not issue a token")
		return
	}
	if err := s.st.putToken(refresh, rt); err != nil {
		tokenError(w, http.StatusInternalServerError, "server_error", "could not issue a token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessEnd.Sub(now).Seconds()),
		"refresh_token": refresh,
		"scope":         scope,
	}, false)
}

// agentGone is an agent past the end its box set. The service stops
// admitting it by its own clock, without waiting for a roster.
func (s *Server) agentGone(a agentRow) bool {
	return !s.now().Before(a.Expires)
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc}, false)
}

// serveRevoke is RFC 7009: revoking a refresh token revokes its family. It
// answers 200 whether or not the token was known.
func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
	readDeadline(w)
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
		return
	}
	c, ok := s.authenticateClient(r)
	if !ok {
		tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}
	tok := r.PostForm.Get("token")
	if t, ok, err := s.st.token(tok); err == nil && ok && t.ClientID == c.ID {
		_ = s.st.revokeToken(tok)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// --------------------------------------------------------------------------
// The resource server's side: checking a bearer token at /mcp
// --------------------------------------------------------------------------

// Subject is who a token acts as. Today that is always an agent of one home.
// A later Sourceful staff principal fits here with Kind "staff", a staff id
// and no home of its own: it reaches only homes with an active support
// grant, each through that grant's agent.
type Subject struct {
	Kind string // SubjectAgent
	// Shard names the shard that held the home when the owner approved,
	// so a router can send the token on; "" with one shard.
	Shard string
	Home  string
	// Agent is the roster device id; Key the agent's X25519 public key,
	// as the roster lists it; Kid its key in the keys part.
	Agent string
	Key   []byte
	Kid   string
}

// SubjectAgent is a personal agent an owner approved.
const SubjectAgent = "agent"

// Grant is what one valid access token allows: the scopes the token
// carries that the box still grants its agent, as the newest roster lists
// them. An owner who narrows the grant narrows the token at once; wider
// rights need a new consent, so a token never holds more than its client
// was given.
type Grant struct {
	Subject  Subject
	ClientID string
	Scopes   []string
	// Ops and Caps are the grant's operations and caps. The service may
	// hold a call to them before the box does; it never loosens them.
	Ops     []string
	Caps    protocol.Caps
	Expires time.Time
	// AgentExpires is when the box ends the agent.
	AgentExpires time.Time
}

// Has reports whether the grant carries a scope.
func (g *Grant) Has(scope string) bool { return slices.Contains(g.Scopes, scope) }

// AuthError is why a request carries no usable token.
type AuthError struct {
	Status int    // 401 or 403
	Code   string // "", invalid_token, insufficient_scope
	Desc   string
	Scope  string // the scopes the operation needs
}

// Authenticate checks a request's bearer token for /mcp: an access token
// this server issued, not expired, for this resource, whose agent the owner
// has not removed. Tokens in the query string are not read.
func (s *Server) Authenticate(r *http.Request) (*Grant, *AuthError) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return nil, &AuthError{Status: http.StatusUnauthorized, Scope: strings.Join(ReadScopes, " ")}
	}
	invalid := &AuthError{Status: http.StatusUnauthorized, Code: "invalid_token", Desc: "the access token is not valid"}
	tok = strings.TrimSpace(tok)
	if !tokenShape(tok, accessPrefix) {
		return nil, invalid
	}
	t, ok, err := s.st.token(tok)
	if err != nil || !ok || t.Kind != kindAccess || !s.now().Before(t.Expires) {
		return nil, invalid
	}
	if t.Resource != Resource {
		return nil, &AuthError{Status: http.StatusUnauthorized, Code: "invalid_token", Desc: "the access token is for another resource"}
	}
	a, ok, err := s.st.agent(t.Home, t.Agent)
	if err != nil || !ok {
		return nil, &AuthError{Status: http.StatusUnauthorized, Code: "invalid_token", Desc: "the owner removed this assistant"}
	}
	if s.agentGone(a) {
		return nil, &AuthError{Status: http.StatusUnauthorized, Code: "invalid_token", Desc: "this assistant's access ran out"}
	}
	return &Grant{
		Subject:  Subject{Kind: SubjectAgent, Shard: a.Shard, Home: a.Home, Agent: a.Agent, Key: a.Key, Kid: a.Kid},
		ClientID: t.ClientID, Scopes: intersect(splitScope(t.Scope), a.Scopes), Ops: a.Ops, Caps: a.Caps,
		Expires: t.Expires, AgentExpires: a.Expires,
	}, nil
}

// Challenge writes a 401 or 403 with its WWW-Authenticate header, and a
// JSON body for clients that show one.
func Challenge(w http.ResponseWriter, e *AuthError) {
	parts := []string{fmt.Sprintf("resource_metadata=%q", ResourceMetadataURL)}
	if e.Code != "" {
		parts = append(parts, fmt.Sprintf("error=%q", e.Code))
	}
	if e.Desc != "" {
		parts = append(parts, fmt.Sprintf("error_description=%q", e.Desc))
	}
	if e.Scope != "" {
		parts = append(parts, fmt.Sprintf("scope=%q", e.Scope))
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(parts, ", "))
	body := map[string]string{"error": e.Code, "error_description": e.Desc}
	if e.Code == "" {
		body = map[string]string{"error": "unauthorized", "error_description": "a bearer token from " + Issuer + " is required"}
	}
	writeJSON(w, e.Status, body, false)
}

// InsufficientScope is the 403 that asks the client to step up.
func InsufficientScope(scopes ...string) *AuthError {
	return &AuthError{Status: http.StatusForbidden, Code: "insufficient_scope",
		Desc: "this needs more rights; ask the owner to approve them", Scope: strings.Join(scopes, " ")}
}

// readDeadline bounds how long a client may take to send its request's
// body. The server sets no ReadTimeout of its own, since its WebSockets set
// their own deadlines.
func readDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(10 * time.Second))
}
