package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
)

var verifierRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// Token prefixes, so a leaked token is recognisable for what it is.
const (
	accessPrefix  = "ftwat_"
	refreshPrefix = "ftwrt_"
)

func (s *Server) serveToken(w http.ResponseWriter, r *http.Request) {
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
	if c.ClientID != cl.ID || subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(c.Challenge)) != 1 ||
		(f.Get("redirect_uri") != "" && f.Get("redirect_uri") != c.RedirectURI) {
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
	fresh, err := s.st.rotate(tok)
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
	if !a.Expires.IsZero() && a.Expires.Before(refreshEnd) {
		refreshEnd = a.Expires
	}
	accessEnd := now.Add(AccessTTL)
	if accessEnd.After(refreshEnd) {
		accessEnd = refreshEnd
	}
	access, refresh := accessPrefix+randomToken(32), refreshPrefix+randomToken(32)
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

func (s *Server) agentGone(a agentRow) bool {
	return !a.Expires.IsZero() && !s.now().Before(a.Expires)
}

func tokenError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc}, false)
}

// serveRevoke is RFC 7009: revoking a refresh token revokes its family. It
// answers 200 whether or not the token was known.
func (s *Server) serveRevoke(w http.ResponseWriter, r *http.Request) {
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
	Kind  string // SubjectAgent
	Shard int
	Home  string
	// Agent is the roster device id; Key the agent's X25519 public key,
	// as the roster lists it; Kid its key in the keys part.
	Agent string
	Key   []byte
	Kid   string
}

// SubjectAgent is a personal agent an owner approved.
const SubjectAgent = "agent"

// Grant is what one valid access token allows.
type Grant struct {
	Subject  Subject
	ClientID string
	Scopes   []string
	Expires  time.Time
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
	t, ok, err := s.st.token(strings.TrimSpace(tok))
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
		ClientID: t.ClientID, Scopes: splitScope(t.Scope), Expires: t.Expires,
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
