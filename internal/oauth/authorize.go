package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// codeAlphabet makes the short code: no 0/O, 1/I or L to misread.
const codeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// codeLen gives about 29 bits. A code finds a request for the box's page and
// proves nothing: the owner still approves on their own box.
const codeLen = 6

var challengeRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// authorize request parameters, after the checks that allow a redirect.
type authRequest struct {
	client      client
	redirectURI string
	state       string
	challenge   string
	scope       []string
}

func (s *Server) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, v := range q {
		if len(v) > 1 {
			s.authorizePage(w, http.StatusBadRequest, pageError{Title: "This link is not valid",
				Text: fmt.Sprintf("The parameter %s appears more than once.", k)})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	// Until client and redirect URI check out, nothing goes back to the
	// client: a bad request could otherwise send the browser anywhere.
	c, err := s.resolveClient(ctx, q.Get("client_id"))
	if err != nil {
		s.authorizePage(w, http.StatusBadRequest, pageError{Title: "This assistant is not known here",
			Text: "The link names a client that FTW Cloud cannot check. Ask the assistant to connect again."})
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(c.RedirectURIs) == 1 {
		redirect = c.RedirectURIs[0]
	}
	if redirect == "" || checkRedirect(redirect) != nil || !redirectMatches(c.RedirectURIs, redirect) {
		s.authorizePage(w, http.StatusBadRequest, pageError{Title: "This link is not valid",
			Text: "The assistant asked to return somewhere it did not register."})
		return
	}
	req := authRequest{client: c, redirectURI: redirect, state: q.Get("state")}
	fail := func(code, desc string) {
		http.Redirect(w, r, authorizationError(redirect, code, desc, req.state), http.StatusFound)
	}
	if len(req.state) > 1024 {
		fail("invalid_request", "state is too long")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code")
		return
	}
	if q.Get("code_challenge_method") != "S256" || !challengeRE.MatchString(q.Get("code_challenge")) {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	req.challenge = q.Get("code_challenge")
	if res := q.Get("resource"); res != "" && !sameResource(res) {
		fail("invalid_target", "this server issues tokens only for "+Resource)
		return
	}
	for _, sc := range splitScope(q.Get("scope")) {
		switch {
		case sc == "offline_access":
			// Refresh tokens come anyway.
		case validScope(sc):
			if !slices.Contains(req.scope, sc) {
				req.scope = append(req.scope, sc)
			}
		default:
			fail("invalid_scope", "unknown scope "+sc)
			return
		}
	}
	if len(req.scope) == 0 {
		req.scope = slices.Clone(ReadScopes)
	}
	if !s.authorizeLimit.allow(s.now()) {
		fail("temporarily_unavailable", "too many requests; try again shortly")
		return
	}

	// The agent's key pair comes first; only its public half leaves the
	// keys part, to be shown to the owner and listed by the box.
	kid, pub, err := s.keys.New(ctx)
	if err != nil {
		s.log.Warn("the keys part could not make an agent key", "err", err)
		fail("temporarily_unavailable", "assistants cannot connect right now")
		return
	}
	now := s.now()
	rid, browser := randomToken(16), randomToken(32)
	// The host the owner is shown: the metadata document's, or for a
	// registered client the redirect URI's, since the name it registered
	// proves nothing.
	host := c.Host
	if !isCIMD(c.ID) {
		if u, err := url.Parse(redirect); err == nil {
			host = u.Hostname()
		}
	}
	con := consent{ClientID: c.ID, ClientName: c.Name, ClientHost: host, Verified: c.Verified, RedirectURI: redirect,
		State: req.state, Challenge: req.challenge, Scope: strings.Join(req.scope, " "), Resource: Resource,
		Kid: kid, AgentKey: pub, Created: now, Expires: now.Add(RequestTTL), Status: statusPending}
	for try := 0; ; try++ {
		con.Code = shortCode()
		if con.Offer, err = s.signOffer(ctx, buildOffer(con)); err != nil {
			s.log.Warn("the keys part could not sign an offer", "err", err)
			break
		}
		err = s.st.putConsent(rid, browser, con)
		if err == nil || try == 3 {
			break
		}
	}
	if err != nil {
		_ = s.keys.Forget(ctx, kid)
		fail("server_error", "could not start the request")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName(rid), Value: browser, Path: "/", MaxAge: int(RequestTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	s.consentPage(w, rid, con)
}

// sameResource compares a resource parameter with Resource, taking
// uppercase in the scheme and host, and a trailing slash, as the same.
func sameResource(res string) bool {
	u, err := url.Parse(res)
	if err != nil || u.Fragment != "" || u.RawQuery != "" {
		return false
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String() == Resource
}

func validScope(sc string) bool { return slices.Contains(AllScopes, sc) }

func cookieName(rid string) string { return "__Host-ftw-consent-" + rid[:8] }

func shortCode() string {
	b := make([]byte, codeLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

// normalizeCode reads a code as an owner may type it.
func normalizeCode(s string) string {
	s = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(s))
	if len(s) != codeLen || strings.Trim(s, codeAlphabet) != "" {
		return ""
	}
	return s
}

// authorizationResponse adds the parameters to the client's redirect URI,
// with iss, as RFC 9207 asks of every response.
func authorizationResponse(redirect string, params url.Values) string {
	u, _ := url.Parse(redirect)
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	q.Set("iss", Issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

func authorizationError(redirect, code, desc, state string) string {
	p := url.Values{"error": {code}, "error_description": {desc}}
	if state != "" {
		p.Set("state", state)
	}
	return authorizationResponse(redirect, p)
}

// --------------------------------------------------------------------------
// The request, for the app and the box's page
// --------------------------------------------------------------------------

type requestView struct {
	Request string `json:"request,omitempty"`
	// Offer is the signed grant offer, base64url, as the link carries it.
	Offer    string       `json:"offer"`
	Status   string       `json:"status"`
	Code     string       `json:"code"`
	Client   clientView   `json:"client"`
	Redirect redirectView `json:"redirect"`
	Scopes   []string     `json:"scopes"`
	Agent    agentKeyView `json:"agent"`
	Expires  int64        `json:"expiresAtMs"`
}

type clientView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host,omitempty"`
	Verified bool   `json:"verified"`
}

type redirectView struct {
	Host string `json:"host"`
	// Local is a client on the owner's own computer.
	Local bool `json:"local"`
}

type agentKeyView struct {
	// Key is the agent's X25519 public key, base64url: what the box lists.
	Key string `json:"key"`
	ID  string `json:"id"`
}

func (s *Server) view(c consent) requestView {
	u, _ := url.Parse(c.RedirectURI)
	status := c.Status
	if status == statusPending && !s.now().Before(c.Expires) {
		status = "expired"
	}
	return requestView{Offer: c.Offer, Status: status, Code: c.Code,
		Client:   clientView{ID: c.ClientID, Name: c.ClientName, Host: c.ClientHost, Verified: c.Verified},
		Redirect: redirectView{Host: u.Hostname(), Local: u.Scheme == "http" && isLoopback(u.Hostname())},
		Scopes:   splitScope(c.Scope),
		Agent:    agentKeyView{Key: base64.RawURLEncoding.EncodeToString(c.AgentKey), ID: cloudwire.DeviceID(c.AgentKey)},
		Expires:  c.Expires.UnixMilli()}
}

// serveRequest gives the app what it shows the owner before they approve.
func (s *Server) serveRequest(w http.ResponseWriter, r *http.Request) {
	c, ok, err := s.st.consentByRID(r.PathValue("rid"))
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	allowApp(w, r)
	v := s.view(c)
	v.Request = r.PathValue("rid")
	writeJSON(w, http.StatusOK, v, false)
}

// serveRequestByCode finds a request by the code an owner typed on the box's
// page or in the app, once: a short code cannot carry the agent's key, so
// it fetches the signed offer. Lookups are rate limited for everyone
// together, and a code works once: it lasts ten minutes and has about 29
// bits, and finding one shows only an offer the owner must still approve.
func (s *Server) serveRequestByCode(w http.ResponseWriter, r *http.Request) {
	if !s.lookupLimit.allow(s.now()) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many lookups", http.StatusTooManyRequests)
		return
	}
	code := normalizeCode(r.URL.Query().Get("code"))
	if code == "" {
		http.NotFound(w, r)
		return
	}
	c, ok, err := s.st.spendCode(code, s.now())
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	// The box's page fetches it from the owner's browser, on whatever
	// address the box has at home.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, s.view(c), false)
}

func allowApp(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") == AppOrigin {
		w.Header().Set("Access-Control-Allow-Origin", AppOrigin)
		w.Header().Set("Vary", "Origin")
	}
}

// serveDeny ends a pending request without approval: the owner said no, or
// the person at the computer cancelled.
func (s *Server) serveDeny(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("rid")
	c, ok, err := s.st.deny(rid)
	if err != nil {
		http.Error(w, "could not deny", http.StatusInternalServerError)
		return
	}
	if ok {
		_ = s.keys.Forget(r.Context(), c.Kid)
		s.hub.notify(string(hash(rid)))
	}
	allowApp(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// --------------------------------------------------------------------------
// The event stream the page waits on
// --------------------------------------------------------------------------

// keepAlive is how often a quiet stream sends a comment, and looks at the
// request again in case another process changed it.
const keepAlive = 20 * time.Second

func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	rid := r.PathValue("rid")
	if _, ok, err := s.st.consentByRID(rid); err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	// Only the browser that started the request gets the code.
	var browser string
	if ck, err := r.Cookie(cookieName(rid)); err == nil && s.st.browserMatches(rid, ck.Value) {
		browser = ck.Value
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	wake, done := s.hub.subscribe(string(hash(rid)))
	defer done()
	tick := time.NewTicker(keepAlive)
	defer tick.Stop()
	// A pending request's end does not move; once it changes state the
	// stream is over.
	expiry := time.NewTimer(RequestTTL)
	defer expiry.Stop()
	for {
		c, ok, err := s.st.consentByRID(rid)
		if err != nil || !ok {
			return
		}
		if end := s.event(w, rid, browser, c); end {
			flusher.Flush()
			return
		}
		flusher.Flush()
		expiry.Reset(max(c.Expires.Sub(s.now()), 0))
		select {
		case <-r.Context().Done():
			return
		case <-wake:
		case <-expiry.C:
		case <-tick.C:
			_, _ = fmt.Fprint(w, ":\n\n")
		}
	}
}

// event writes the request's state. end is true when the stream is done.
func (s *Server) event(w http.ResponseWriter, rid, browser string, c consent) (end bool) {
	send := func(name, redirect string) {
		data := "{}"
		if redirect != "" && browser != "" {
			data = fmt.Sprintf(`{"redirect":%q}`, redirect)
		}
		_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
	}
	expired := !s.now().Before(c.Expires)
	switch {
	case c.Status == statusApproved:
		if browser == "" {
			send("approved", "")
			return true
		}
		// A new code for each delivery: a browser that reconnects gets one
		// that works, and the earlier one stops working.
		code := randomToken(32)
		if err := s.st.issueCode(rid, code, s.now().Add(CodeTTL)); err != nil {
			send("expired", "")
			return true
		}
		p := url.Values{"code": {code}}
		if c.State != "" {
			p.Set("state", c.State)
		}
		send("approved", authorizationResponse(c.RedirectURI, p))
		return true
	case c.Status == statusDenied:
		send("denied", authorizationError(c.RedirectURI, "access_denied", "the owner did not approve", c.State))
		return true
	case expired:
		send("expired", authorizationError(c.RedirectURI, "access_denied", "the request ran out before the owner approved", c.State))
		return true
	default:
		_, _ = fmt.Fprintf(w, "event: pending\ndata: {\"expiresAtMs\":%d}\n\n", c.Expires.UnixMilli())
		return false
	}
}
