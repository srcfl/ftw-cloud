package oauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/srcfl/ftw/go/protocol"
)

// client is a client as the authorize and token endpoints see it, from a
// metadata document or from a registration.
type client struct {
	ID   string
	Name string
	// Host is where the name came from: the host of the metadata
	// document's URL, which vouches for it, or the client_uri a registration
	// claimed, which does not.
	Host string
	// Verified is a client FTW Cloud knows: a metadata document at one of
	// verifiedClients.
	Verified     bool
	RedirectURIs []string
	AuthMethod   string
	secret       []byte // hash, for a registered confidential client
}

var errUnknownClient = errors.New("unknown client")

// resolveClient finds the client a client_id names.
func (s *Server) resolveClient(ctx context.Context, id string) (client, error) {
	if id == protocol.SupportClientID {
		// Support's offers come from its own tooling, never through this
		// page: the box and the app trust that client id for support.
		return client{}, errUnknownClient
	}
	if isCIMD(id) {
		md, err := s.fetch.get(ctx, id)
		if err != nil {
			return client{}, err
		}
		u, _ := url.Parse(id)
		host, _ := asciiHost(u.Hostname()) // checkCIMDURL refused one without
		return client{ID: id, Name: md.ClientName, Host: host, Verified: verifiedClient(id), RedirectURIs: md.RedirectURIs,
			AuthMethod: authNone}, nil
	}
	c, ok, err := s.st.client(id)
	if err != nil {
		return client{}, err
	}
	if !ok {
		return client{}, errUnknownClient
	}
	host := ""
	if u, err := url.Parse(c.URI); err == nil {
		host, _ = asciiHost(u.Hostname())
	}
	return client{ID: c.ID, Name: c.Name, Host: host, RedirectURIs: c.RedirectURIs, AuthMethod: c.AuthMethod, secret: c.Secret}, nil
}

// cursorRedirect is the one custom-scheme redirect URI FTW Cloud accepts:
// Cursor's desktop app, which Grok Bot and the Cursor IDE use to finish an
// MCP sign-in. It must match byte for byte; no other custom scheme, host,
// path, query or casing of it passes. Its client still needs PKCE S256 at
// /authorize and the same redirect URI again at /token.
const cursorRedirect = "cursor://anysphere.cursor-mcp/oauth/callback"

// localRedirect reports whether a redirect URI that checkRedirect accepted
// ends at a program on the owner's computer rather than a website: loopback
// http, or the Cursor callback, which whatever app claimed the cursor:
// scheme receives. The owner is warned to approve only what they started.
func localRedirect(u *url.URL) bool {
	return u.String() == cursorRedirect || u.Scheme == "http" && isLoopback(u.Hostname())
}

// checkRedirect holds a redirect URI to the rules: https, or http to this
// computer's loopback for a client that runs on it. No fragment and no
// credentials. Custom schemes are refused, as the MCP spec asks, except the
// exact cursorRedirect, and so is a host with no ASCII form (asciiHost).
func checkRedirect(raw string) error {
	if raw == cursorRedirect {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") || u.Host == "" || len(raw) > 2048 {
		return fmt.Errorf("redirect URI %q is not allowed", raw)
	}
	if _, ok := asciiHost(u.Hostname()); !ok {
		return fmt.Errorf("redirect URI %q has a host with no ASCII form", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("redirect URI %q is neither https nor loopback http", raw)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// redirectMatches compares a redirect URI with the registered ones: exactly,
// or for a loopback URI with any port, since a client on the owner's
// computer takes whatever port is free (RFC 8252).
func redirectMatches(registered []string, given string) bool {
	g, err := url.Parse(given)
	if err != nil {
		return false
	}
	for _, r := range registered {
		if r == given {
			return true
		}
		u, err := url.Parse(r)
		if err != nil || u.Scheme != "http" || g.Scheme != "http" || !isLoopback(u.Hostname()) {
			continue
		}
		if u.Hostname() == g.Hostname() && u.Path == g.Path && u.RawQuery == g.RawQuery && g.User == nil && g.Fragment == "" {
			return true
		}
	}
	return false
}

// --------------------------------------------------------------------------
// Dynamic registration (RFC 7591), kept for clients without metadata
// documents
// --------------------------------------------------------------------------

// maxClients bounds registrations kept.
const maxClients = 50_000

type registration struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

func (s *Server) serveRegister(w http.ResponseWriter, r *http.Request) {
	if s.limited(&s.registerLimit, s.registerByIP, r) {
		w.Header().Set("Retry-After", "10")
		registerError(w, http.StatusTooManyRequests, "invalid_client_metadata", "too many registrations; try again shortly")
		return
	}
	readDeadline(w)
	var reg registration
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err != nil || json.Unmarshal(body, &reg) != nil {
		registerError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is not a JSON object")
		return
	}
	if len(reg.RedirectURIs) == 0 || len(reg.RedirectURIs) > 16 {
		registerError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must list between 1 and 16 URIs")
		return
	}
	for _, u := range reg.RedirectURIs {
		if err := checkRedirect(u); err != nil {
			registerError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	method := reg.TokenEndpointAuthMethod
	if method == "" {
		method = authNone
	}
	if method != authNone && method != authSecretPost && method != authSecretBasic {
		registerError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic")
		return
	}
	// Grants this server does not offer are left out of what it registers
	// (RFC 7591 lets it replace them), as for a metadata document.
	grants := intersect(reg.GrantTypes, []string{grantCode, grantRefresh})
	if len(reg.GrantTypes) == 0 {
		grants = []string{grantCode}
	}
	if !slices.Contains(grants, grantCode) || len(reg.ResponseTypes) > 0 && !slices.Contains(reg.ResponseTypes, "code") {
		registerError(w, http.StatusBadRequest, "invalid_client_metadata", "the authorization_code grant, with response type code, is required")
		return
	}
	for _, sc := range splitScope(reg.Scope) {
		if !validScope(sc) {
			registerError(w, http.StatusBadRequest, "invalid_client_metadata", "unknown scope "+sc)
			return
		}
	}
	name := cleanName(reg.ClientName)
	if name == "" {
		name = "An unnamed assistant"
	}
	if reg.ClientURI != "" {
		if u, err := url.Parse(reg.ClientURI); err != nil || u.Scheme != "https" {
			reg.ClientURI = ""
		} else if _, ok := asciiHost(u.Hostname()); !ok {
			reg.ClientURI = ""
		}
	}
	if s.st.countClients() >= maxClients {
		registerError(w, http.StatusServiceUnavailable, "invalid_client_metadata", "registration is full")
		return
	}
	c := dcrClient{ID: "ftwc_" + randomToken(16), AuthMethod: method, Name: name, URI: reg.ClientURI, RedirectURIs: reg.RedirectURIs}
	var secret string
	if method != authNone {
		secret = "ftws_" + randomToken(32)
		c.Secret = hash(secret)
	}
	if err := s.st.putClient(c, s.now()); err != nil {
		registerError(w, http.StatusInternalServerError, "invalid_client_metadata", "could not register")
		return
	}
	out := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        s.now().Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": method,
		"grant_types":                grants,
		"response_types":             []string{"code"},
	}
	if reg.ClientURI != "" {
		out["client_uri"] = reg.ClientURI
	}
	if secret != "" {
		out["client_secret"] = secret
		out["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, out, false)
}

func registerError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc}, false)
}

// authenticateClient checks a token or revocation request's client: its id
// in the form or in Basic, and its secret if it has one.
func (s *Server) authenticateClient(r *http.Request) (client, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return client{}, false
	}
	var c client
	if isCIMD(id) {
		// A metadata document's client is public; it was checked when the
		// consent began, and its id is bound to the consent.
		c = client{ID: id, AuthMethod: authNone}
	} else {
		dc, ok, err := s.st.client(id)
		if err != nil || !ok {
			return client{}, false
		}
		c = client{ID: dc.ID, AuthMethod: dc.AuthMethod, secret: dc.Secret}
	}
	switch c.AuthMethod {
	case authNone:
		return c, secret == ""
	default:
		if secret == "" || len(c.secret) == 0 {
			return client{}, false
		}
		if subtle.ConstantTimeCompare(hash(secret), c.secret) != 1 {
			return client{}, false
		}
		s.st.clientUsed(c.ID, s.now())
		return c, true
	}
}
