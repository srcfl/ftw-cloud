package oauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// rig is the authorization server with a real keys part behind it, a
// client's metadata document on its own https server, and a clock.
type rig struct {
	t      *testing.T
	s      *Server
	keys   *keys.Client
	srv    *httptest.Server
	cimd   *httptest.Server
	docs   map[string]string
	docsMu sync.Mutex
	clock  struct {
		sync.Mutex
		now time.Time
	}
}

const (
	cimdID   = "https://example.com/oauth/client.json"
	cimdBack = "https://example.com/callback"
	home     = "homehomehomehomehomehomeho"
)

func newRig(t *testing.T) *rig {
	t.Helper()
	g := &rig{t: t, docs: map[string]string{}}
	g.clock.now = time.Now()
	ks, err := keys.NewServer(t.TempDir(), mustFileSealer(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	g.keys = ks.Local()

	g.docs["/oauth/client.json"] = `{"client_id":"` + cimdID + `","client_name":"Claude","redirect_uris":["` + cimdBack + `","http://127.0.0.1/cb"]}`
	g.cimd = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.docsMu.Lock()
		doc, ok := g.docs[r.URL.Path]
		g.docsMu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, doc)
	}))
	t.Cleanup(g.cimd.Close)
	pool := x509.NewCertPool()
	pool.AddCert(g.cimd.Certificate())

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	g.s, err = newServer(filepath.Join(t.TempDir(), "oauth.db"), g.keys, log, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.s.Close() })
	g.s.now = g.now
	g.s.fetch.now = g.now
	// example.com is the test server, on loopback, which the fence would
	// refuse: only this rig lets it through.
	g.s.fetch.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host == "example.com" {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	g.s.fetch.public = func(a netip.Addr) bool { return a == netip.MustParseAddr("127.0.0.1") || publicAddr(a) }
	g.s.fetch.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, g.cimd.Listener.Addr().String())
	}
	mux := http.NewServeMux()
	g.s.Mount(mux)
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go g.s.Run(ctx)
	return g
}

func mustFileSealer(t *testing.T) keys.Sealer {
	s, err := keys.FileSealerFromKey(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (g *rig) now() time.Time {
	g.clock.Lock()
	defer g.clock.Unlock()
	return g.clock.now
}

func (g *rig) advance(d time.Duration) {
	g.clock.Lock()
	g.clock.now = g.clock.now.Add(d)
	g.clock.Unlock()
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func pkce() (verifier, challenge string) {
	verifier = randomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// flow is one authorization in progress, as the client and its browser hold
// it.
type flow struct {
	verifier, state string
	rid             string
	cookie          *http.Cookie
	view            requestView
}

func (g *rig) authorizeParams(clientID, redirect, scope string) (url.Values, *flow) {
	verifier, challenge := pkce()
	f := &flow{verifier: verifier, state: randomToken(8)}
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {f.state}, "resource": {Resource}}
	if scope != "" {
		q.Set("scope", scope)
	}
	return q, f
}

var ridRE = regexp.MustCompile(`data-rid="([A-Za-z0-9_-]+)"`)

// start opens the authorize page and reads what the app would.
func (g *rig) start(clientID, redirect, scope string) *flow {
	g.t.Helper()
	q, f := g.authorizeParams(clientID, redirect, scope)
	resp, err := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		g.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		g.t.Fatalf("authorize: %d %s %s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	m := ridRE.FindSubmatch(body)
	if m == nil {
		g.t.Fatal("no request id on the page")
	}
	f.rid = string(m[1])
	for _, c := range resp.Cookies() {
		if c.Name == cookieName(f.rid) {
			f.cookie = c
		}
	}
	if f.cookie == nil || !f.cookie.Secure || !f.cookie.HttpOnly {
		g.t.Fatalf("the browser's cookie: %+v", f.cookie)
	}
	f.view = g.details(f.rid)
	return f
}

func (g *rig) details(rid string) requestView {
	g.t.Helper()
	resp, err := http.Get(g.srv.URL + "/oauth/requests/" + rid)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	var v requestView
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&v) != nil {
		g.t.Fatalf("request details: %d", resp.StatusCode)
	}
	return v
}

func (f *flow) agentKey(t *testing.T) []byte {
	k, err := base64.RawURLEncoding.DecodeString(f.view.Agent.Key)
	if err != nil || len(k) != 32 {
		t.Fatalf("agent key %q", f.view.Agent.Key)
	}
	return k
}

type event struct{ name, data string }

// events opens the page's stream, as the browser does (with its cookie) or
// as anyone else could (without).
func (g *rig) events(f *flow, withCookie bool) (<-chan event, func()) {
	g.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, g.srv.URL+"/oauth/requests/"+f.rid+"/events", nil)
	if withCookie {
		req.AddCookie(f.cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		g.t.Fatalf("event stream content type %q", ct)
	}
	ch := make(chan event, 16)
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var ev event
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			case line == "" && ev.name != "":
				ch <- ev
				ev = event{}
			}
		}
	}()
	return ch, cancel
}

func next(t *testing.T, ch <-chan event) event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("the stream ended")
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
	return event{}
}

// roster is the box's signed roster arriving, as the uplink hands it on
// after checking the box's signature.
func (g *rig) roster(h string, devs ...cloudwire.Device) {
	g.s.Roster(h, &cloudwire.Roster{RosterSeq: 1, TTLS: 86400, Devices: devs})
	// Run applies it on its own goroutine; a request on the store after
	// this waits for it by draining the queue.
	deadline := time.Now().Add(2 * time.Second)
	for len(g.s.roster) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
}

func agentDevice(key []byte, scopes ...string) cloudwire.Device {
	return cloudwire.Device{ID: cloudwire.DeviceID(key), Key: key, Role: "agent", Scopes: scopes, Epoch: 1, Tun: true}
}

// redirectOf reads the client's redirect from an event.
func redirectOf(t *testing.T, ev event) *url.URL {
	t.Helper()
	var d struct{ Redirect string }
	if json.Unmarshal([]byte(ev.data), &d) != nil || d.Redirect == "" {
		t.Fatalf("event %s carries no redirect: %s", ev.name, ev.data)
	}
	u, err := url.Parse(d.Redirect)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

type tokens struct {
	Access  string `json:"access_token"`
	Type    string `json:"token_type"`
	Expires int    `json:"expires_in"`
	Refresh string `json:"refresh_token"`
	Scope   string `json:"scope"`
	Error   string `json:"error"`
}

func (g *rig) token(form url.Values, basic ...string) (int, tokens) {
	g.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, g.srv.URL+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" {
		g.t.Fatal("a token response may be cached")
	}
	var tk tokens
	_ = json.NewDecoder(resp.Body).Decode(&tk)
	return resp.StatusCode, tk
}

// approve runs a whole consent: the box lists the agent, the page gets the
// code, the client swaps it.
func (g *rig) approve(f *flow, clientID string, scopes ...string) tokens {
	g.t.Helper()
	ch, stop := g.events(f, true)
	defer stop()
	if ev := next(g.t, ch); ev.name != "pending" {
		g.t.Fatalf("first event %q", ev.name)
	}
	if len(scopes) == 0 {
		scopes = []string{ScopeLiveRead, ScopePlanRead}
	}
	g.roster(home, agentDevice(f.agentKey(g.t), scopes...))
	ev := next(g.t, ch)
	if ev.name != "approved" {
		g.t.Fatalf("event %q after the roster", ev.name)
	}
	u := redirectOf(g.t, ev)
	if u.Query().Get("iss") != Issuer || u.Query().Get("state") != f.state || u.Query().Get("code") == "" {
		g.t.Fatalf("redirect %s", u)
	}
	status, tk := g.token(url.Values{"grant_type": {grantCode}, "code": {u.Query().Get("code")}, "client_id": {clientID},
		"code_verifier": {f.verifier}, "redirect_uri": {f.view.redirectURIForTest()}, "resource": {Resource}})
	if status != http.StatusOK || tk.Access == "" || tk.Refresh == "" || tk.Type != "Bearer" {
		g.t.Fatalf("token: %d %+v", status, tk)
	}
	return tk
}

// redirectURIForTest is the redirect the test flows use; requestView shows
// only its host.
func (v requestView) redirectURIForTest() string {
	if v.Redirect.Local {
		return "http://127.0.0.1/cb"
	}
	return cimdBack
}

func (g *rig) bearer(tok string) (*Grant, *AuthError) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return g.s.Authenticate(r)
}

// ---------------------------------------------------------------------------

func TestMetadataNamesTheIssuerAndTheResource(t *testing.T) {
	g := newRig(t)
	var as map[string]any
	getJSON(t, g.srv.URL+"/.well-known/oauth-authorization-server", &as)
	if as["issuer"] != Issuer || as["authorization_response_iss_parameter_supported"] != true ||
		as["client_id_metadata_document_supported"] != true || as["registration_endpoint"] != Issuer+"/oauth/register" {
		t.Fatalf("authorization server metadata: %v", as)
	}
	if m := as["code_challenge_methods_supported"].([]any); len(m) != 1 || m[0] != "S256" {
		t.Fatalf("PKCE methods %v", m)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"} {
		var pr map[string]any
		getJSON(t, g.srv.URL+p, &pr)
		if pr["resource"] != Resource || pr["authorization_servers"].([]any)[0] != Issuer {
			t.Fatalf("%s: %v", p, pr)
		}
	}
}

func getJSON(t *testing.T, u string, v any) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(v) != nil {
		t.Fatalf("GET %s: %d", u, resp.StatusCode)
	}
}

// The whole flow with a client ID metadata document and PKCE, then refresh
// with rotation.
func TestTheFullFlowWithAMetadataDocument(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead+" "+ScopePlanRead+" "+ScopeHistoryRead)
	if f.view.Client.Name != "Claude" || !f.view.Client.Verified || f.view.Client.Host != "example.com" ||
		f.view.Redirect.Host != "example.com" || f.view.Status != statusPending || len(f.view.Code) != codeLen {
		t.Fatalf("what the app sees: %+v", f.view)
	}
	// The box grants less than asked: the token says so.
	tk := g.approve(f, cimdID, ScopeLiveRead, ScopePlanRead)
	if tk.Scope != ScopeLiveRead+" "+ScopePlanRead || tk.Expires <= 0 || tk.Expires > int(AccessTTL.Seconds()) {
		t.Fatalf("token: %+v", tk)
	}
	grant, aerr := g.bearer(tk.Access)
	if aerr != nil {
		t.Fatalf("a fresh token was refused: %+v", aerr)
	}
	key := f.agentKey(t)
	if grant.Subject.Home != home || grant.Subject.Agent != cloudwire.DeviceID(key) || !bytes.Equal(grant.Subject.Key, key) ||
		grant.Subject.Kind != SubjectAgent || grant.ClientID != cimdID || !grant.Has(ScopePlanRead) || grant.Has(ScopeHistoryRead) {
		t.Fatalf("grant: %+v", grant)
	}

	// Refresh rotates: the new pair works, the old refresh token is spent,
	// and using it again revokes the whole family.
	status, tk2 := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}, "resource": {Resource}})
	if status != http.StatusOK || tk2.Refresh == tk.Refresh {
		t.Fatalf("refresh: %d %+v", status, tk2)
	}
	if _, aerr := g.bearer(tk2.Access); aerr != nil {
		t.Fatal("the refreshed token was refused")
	}
	status, _ = g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}})
	if status != http.StatusBadRequest {
		t.Fatalf("a spent refresh token: %d", status)
	}
	if _, aerr := g.bearer(tk2.Access); aerr == nil {
		t.Fatal("a reused refresh token left its family alive")
	}
	status, _ = g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk2.Refresh}, "client_id": {cimdID}})
	if status != http.StatusBadRequest {
		t.Fatalf("the family's newest refresh token: %d", status)
	}
}

// A code works once; presenting it again revokes what it got.
func TestACodeWorksOnce(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {f.verifier}}
	status, tk := g.token(form)
	if status != http.StatusOK {
		t.Fatalf("first use: %d", status)
	}
	if status, _ := g.token(form); status != http.StatusBadRequest {
		t.Fatalf("second use: %d", status)
	}
	if _, aerr := g.bearer(tk.Access); aerr == nil {
		t.Fatal("tokens from a reused code still work")
	}
}

// PKCE: the verifier must match, and nothing but S256 starts a flow.
func TestPKCEIsRequired(t *testing.T) {
	g := newRig(t)
	q, _ := g.authorizeParams(cimdID, cimdBack, "")
	for _, change := range []func(url.Values){
		func(q url.Values) { q.Del("code_challenge") },
		func(q url.Values) { q.Set("code_challenge_method", "plain") },
		func(q url.Values) { q.Del("code_challenge_method") },
		func(q url.Values) { q.Set("code_challenge", "short") },
	} {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = slices.Clone(v)
		}
		change(qq)
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + qq.Encode())
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("iss") != Issuer {
			t.Fatalf("without S256 PKCE: %d %s", resp.StatusCode, loc)
		}
	}

	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	wrong, _ := pkce()
	if status, _ := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {wrong}}); status != http.StatusBadRequest {
		t.Fatalf("a wrong verifier: %d", status)
	}
}

// Before client and redirect URI check out, nothing redirects; after, every
// error goes back with iss.
func TestBadRequestsNeverRedirectSomewhereUnchecked(t *testing.T) {
	g := newRig(t)
	for _, q := range []url.Values{
		{"client_id": {"ftwc_nobody"}, "redirect_uri": {"https://evil.example/cb"}},
		{"client_id": {cimdID}, "redirect_uri": {"https://evil.example/cb"}},
		{"client_id": {cimdID}, "redirect_uri": {"https://example.com/callback/../x"}},
		{"client_id": {"https://example.com/nothing-here.json"}, "redirect_uri": {cimdBack}},
	} {
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Fatalf("%v: %d %q", q, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	q, _ := g.authorizeParams(cimdID, cimdBack, "")
	q.Set("resource", "https://cloud.ftw.energy/other")
	resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_target" || loc.Query().Get("iss") != Issuer || loc.Host != "example.com" {
		t.Fatalf("another resource: %s", loc)
	}
	q.Set("resource", Resource)
	q.Set("scope", "ftw.live.read admin")
	resp, _ = noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	loc, _ = url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" {
		t.Fatalf("an unknown scope: %s", loc)
	}
	// A loopback redirect may take any port.
	q2, _ := g.authorizeParams(cimdID, "http://127.0.0.1:53121/cb", "")
	resp, _ = noFollow.Get(g.srv.URL + "/oauth/authorize?" + q2.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loopback with a port: %d", resp.StatusCode)
	}
}

// Dynamic registration, for clients without a metadata document: public
// and confidential.
func TestTheFullFlowWithDynamicRegistration(t *testing.T) {
	g := newRig(t)
	register := func(body string) (int, map[string]any) {
		resp, err := http.Post(g.srv.URL+"/oauth/register", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	for _, bad := range []string{
		`{"redirect_uris":["myapp://cb"]}`,
		`{"redirect_uris":["http://evil.example/cb"]}`,
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["https://chatgpt.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
		`{"redirect_uris":["https://chatgpt.com/cb"],"grant_types":["client_credentials"]}`,
		`not json`,
	} {
		if status, out := register(bad); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", bad, status, out)
		}
	}

	status, pub := register(`{"client_name":"Grok‮","redirect_uris":["https://grok.example/cb"]}`)
	if status != http.StatusCreated || pub["client_secret"] != nil || pub["client_name"] != "Grok" {
		t.Fatalf("public registration: %d %v", status, pub)
	}
	id := pub["client_id"].(string)
	f := g.start(id, "https://grok.example/cb", "")
	if f.view.Client.Verified || f.view.Client.Name != "Grok" {
		t.Fatalf("a registered client's name is not checked: %+v", f.view.Client)
	}
	ch, stop := g.events(f, true)
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	stop()
	if status, tk := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {id}, "code_verifier": {f.verifier}}); status != http.StatusOK {
		t.Fatalf("public client token: %d %+v", status, tk)
	}

	status, conf := register(`{"client_name":"ChatGPT","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"client_secret_post","grant_types":["authorization_code","refresh_token"]}`)
	if status != http.StatusCreated || conf["client_secret"] == nil {
		t.Fatalf("confidential registration: %d %v", status, conf)
	}
	cid, secret := conf["client_id"].(string), conf["client_secret"].(string)
	f = g.start(cid, "https://chatgpt.com/connector_platform_oauth_redirect", "")
	ch, stop = g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	code = redirectOf(t, next(t, ch)).Query().Get("code")
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cid}, "code_verifier": {f.verifier}}
	if status, _ := g.token(form); status != http.StatusUnauthorized {
		t.Fatalf("no secret: %d", status)
	}
	form.Set("client_secret", "ftws_wrong")
	if status, _ := g.token(form); status != http.StatusUnauthorized {
		t.Fatalf("a wrong secret: %d", status)
	}
	form.Set("client_secret", secret)
	if status, tk := g.token(form); status != http.StatusOK {
		t.Fatalf("the right secret: %d %+v", status, tk)
	}
}

// The page finishes only when the box's roster lists the very key this
// request made, as a device that may open a session; and only the browser
// that started it gets the code.
func TestConsentCompletesOnlyWhenTheRosterListsTheAgent(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	browser, stop := g.events(f, true)
	defer stop()
	stranger, stop2 := g.events(f, false)
	defer stop2()
	if next(t, browser).name != "pending" || next(t, stranger).name != "pending" {
		t.Fatal("not pending at first")
	}
	// Another key, the right key without a tunnel, the right key under
	// another id: none of them approves.
	other := bytes.Repeat([]byte{1}, 32)
	key := f.agentKey(t)
	noTun := agentDevice(key, ScopeLiveRead)
	noTun.Tun = false
	wrongID := agentDevice(key, ScopeLiveRead)
	wrongID.ID = "someone"
	g.roster(home, agentDevice(other, ScopeLiveRead), noTun, wrongID)
	select {
	case ev := <-browser:
		t.Fatalf("event %q before the roster listed the agent", ev.name)
	case <-time.After(100 * time.Millisecond):
	}
	if g.details(f.rid).Status != statusPending {
		t.Fatal("approved without the agent in the roster")
	}

	g.roster(home, agentDevice(key, ScopeLiveRead))
	if ev := next(t, stranger); ev.name != "approved" || strings.Contains(ev.data, "code") {
		t.Fatalf("a stranger's stream got %q %s", ev.name, ev.data)
	}
	if ev := next(t, browser); ev.name != "approved" || redirectOf(t, ev).Query().Get("code") == "" {
		t.Fatal("the browser got no code")
	}
}

// The owner says no, or the request runs out: the page goes back with
// access_denied, and the key is forgotten.
func TestDeniedAndExpiredRequestsEnd(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	resp, _ := http.Post(g.srv.URL+"/oauth/requests/"+f.rid+"/deny", "", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deny: %d", resp.StatusCode)
	}
	ev := next(t, ch)
	if u := redirectOf(t, ev); ev.name != "denied" || u.Query().Get("error") != "access_denied" || u.Query().Get("iss") != Issuer {
		t.Fatalf("after deny: %s %s", ev.name, ev.data)
	}
	// A roster that lists it now is too late.
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	if v := g.details(f.rid); v.Status != statusDenied {
		t.Fatalf("status after deny and roster: %s", v.Status)
	}

	f2 := g.start(cimdID, cimdBack, "")
	g.advance(RequestTTL + time.Second)
	ch2, stop2 := g.events(f2, true)
	defer stop2()
	if ev := next(t, ch2); ev.name != "expired" || redirectOf(t, ev).Query().Get("error") != "access_denied" {
		t.Fatalf("expired: %s %s", ev.name, ev.data)
	}
	g.roster(home, agentDevice(f2.agentKey(t), ScopeLiveRead))
	if v := g.details(f2.rid); v.Status != "expired" {
		t.Fatalf("an expired request was approved: %s", v.Status)
	}
}

// The owner revokes at the box: the next roster leaves the agent out, its
// tokens stop working at once, its refresh token too, and the keys part
// forgets its key.
func TestRevokeAtTheBoxEndsTheTokens(t *testing.T) {
	g := newRig(t)
	var revoked []string
	var mu sync.Mutex
	g.s.OnRevoke = func(h, agent string) {
		mu.Lock()
		revoked = append(revoked, agent)
		mu.Unlock()
	}
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	grant, aerr := g.bearer(tk.Access)
	if aerr != nil {
		t.Fatal(aerr)
	}
	// The keys part holds the key: a session opens.
	if _, _, err := g.keys.Open(context.Background(), grant.Subject.Kid, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatalf("an approved key does not open: %v", err)
	}

	g.roster(home) // the agent is gone
	if _, aerr := g.bearer(tk.Access); aerr == nil || aerr.Status != http.StatusUnauthorized || aerr.Code != "invalid_token" {
		t.Fatalf("after revoke: %+v", aerr)
	}
	if status, _ := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}}); status != http.StatusBadRequest {
		t.Fatalf("refresh after revoke: %d", status)
	}
	if _, _, err := g.keys.Open(context.Background(), grant.Subject.Kid, bytes.Repeat([]byte{2}, 32)); !errors.Is(err, keys.ErrUnknownKey) {
		t.Fatalf("the key outlived its agent: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(revoked) != 1 || revoked[0] != grant.Subject.Agent {
		t.Fatalf("revoked %v", revoked)
	}
}

// An agent whose time the box set runs out fails, and is swept.
func TestAnExpiredAgentFails(t *testing.T) {
	g := newRig(t)
	end := g.now().Add(2 * time.Hour)
	g.s.AgentExpiry = func(cloudwire.Device) time.Time { return end }
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	if _, aerr := g.bearer(tk.Access); aerr != nil {
		t.Fatal(aerr)
	}
	g.advance(2*time.Hour + time.Second)
	if _, aerr := g.bearer(tk.Access); aerr == nil {
		t.Fatal("an expired agent's token works")
	}
	if status, _ := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}}); status != http.StatusBadRequest {
		t.Fatalf("refresh after the agent ended: %d", status)
	}
	g.s.sweep(context.Background())
	if _, ok, _ := g.s.st.agent(home, cloudwire.DeviceID(f.agentKey(t))); ok {
		t.Fatal("the sweep left an expired agent")
	}
}

// A token for another resource is refused at /mcp, whatever else is right
// about it; and so is a token that is not an access token.
func TestWrongAudienceIsRefused(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	agent := cloudwire.DeviceID(f.agentKey(t))
	other := "ftwat_" + randomToken(32)
	if err := g.s.st.putToken(other, tokenRow{Kind: kindAccess, Family: []byte("f"), ClientID: cimdID, Home: home,
		Agent: agent, Scope: ScopeLiveRead, Resource: "https://cloud.ftw.energy/other", Expires: g.now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, aerr := g.bearer(other); aerr == nil || aerr.Status != http.StatusUnauthorized {
		t.Fatal("a token for another resource was accepted")
	}
	if _, aerr := g.bearer(tk.Refresh); aerr == nil {
		t.Fatal("a refresh token was accepted as an access token")
	}
	status, _ := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID},
		"resource": {"https://elsewhere.example/mcp"}})
	if status != http.StatusBadRequest {
		t.Fatalf("refresh for another resource: %d", status)
	}
	// A token in the query string is not read.
	r := httptest.NewRequest(http.MethodPost, "/mcp?access_token="+tk.Access, nil)
	if _, aerr := g.s.Authenticate(r); aerr == nil {
		t.Fatal("a token in the query string was read")
	}
}

// The challenges: 401 names the resource metadata and the scopes; 403 asks
// for the scope the operation needs.
func TestChallenges(t *testing.T) {
	w := httptest.NewRecorder()
	Challenge(w, &AuthError{Status: http.StatusUnauthorized, Scope: ScopeLiveRead})
	h := w.Header().Get("WWW-Authenticate")
	if w.Code != 401 || !strings.HasPrefix(h, "Bearer ") || !strings.Contains(h, `resource_metadata="`+ResourceMetadataURL+`"`) ||
		!strings.Contains(h, `scope="ftw.live.read"`) {
		t.Fatalf("401: %d %s", w.Code, h)
	}
	w = httptest.NewRecorder()
	Challenge(w, InsufficientScope(ScopeDispatchHold))
	h = w.Header().Get("WWW-Authenticate")
	if w.Code != 403 || !strings.Contains(h, `error="insufficient_scope"`) || !strings.Contains(h, `scope="ftw.dispatch.hold"`) ||
		!strings.Contains(h, "resource_metadata=") {
		t.Fatalf("403: %d %s", w.Code, h)
	}
}

// The box's page finds a request by its code, as an owner types it.
func TestTheBoxPageFindsARequestByItsCode(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	typed := strings.ToLower(f.view.Code[:3]) + " - " + f.view.Code[3:]
	var v requestView
	getJSON(t, g.srv.URL+"/oauth/requests?code="+url.QueryEscape(typed), &v)
	if v.Agent.Key != f.view.Agent.Key || v.Request != "" {
		t.Fatalf("by code: %+v", v)
	}
	resp, _ := http.Get(g.srv.URL + "/oauth/requests?code=ZZZZZZ")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown code: %d", resp.StatusCode)
	}
	// Lookups are rate limited for everyone together.
	limited := false
	for range 60 {
		resp, _ := http.Get(g.srv.URL + "/oauth/requests?code=ZZZZZZ")
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("code lookups are not limited")
	}
}

// The page says who is asking, where the browser goes back, and that a
// loopback redirect is a program on this computer; and it carries a QR and
// the app link, under a strict content security policy.
func TestTheConsentPage(t *testing.T) {
	g := newRig(t)
	q, _ := g.authorizeParams(cimdID, "http://127.0.0.1:8123/cb", ScopeLiveRead+" "+ScopeDispatchHold)
	resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	for _, want := range []string{"Let Claude into your home?", "Identified by example.com", "127.0.0.1:8123",
		"a program on this computer", "<svg", AppLink, scopeWords[ScopeDispatchHold], "Control lasts minutes"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the page lacks %q", want)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP %q", csp)
	}
	// A name with markup in it is text.
	g.docsMu.Lock()
	g.docs["/oauth/evil.json"] = `{"client_id":"https://example.com/oauth/evil.json","client_name":"<script>alert(1)</script>","redirect_uris":["https://example.com/cb"]}`
	g.docsMu.Unlock()
	q, _ = g.authorizeParams("https://example.com/oauth/evil.json", "https://example.com/cb", "")
	resp, _ = noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	body, _ = io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("<script>alert")) {
		t.Fatal("a client's name was put on the page as markup")
	}
}

// Requests for keys are bounded: the authorize endpoint is rate limited
// for everyone together, since each request makes a key.
func TestAuthorizeIsRateLimited(t *testing.T) {
	g := newRig(t)
	limited := false
	for range 40 {
		q, _ := g.authorizeParams(cimdID, cimdBack, "")
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
		if resp.StatusCode == http.StatusFound {
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if loc.Query().Get("error") == "temporarily_unavailable" {
				limited = true
				break
			}
		}
	}
	if !limited {
		t.Fatal("authorize is not limited")
	}
}

// flakyKeys is a keys part that is away for a while.
type flakyKeys struct {
	AgentKeys
	mu   sync.Mutex
	down int
}

func (f *flakyKeys) Keep(ctx context.Context, kid string) error {
	f.mu.Lock()
	if f.down > 0 {
		f.down--
		f.mu.Unlock()
		return keys.ErrUnavailable
	}
	f.mu.Unlock()
	return f.AgentKeys.Keep(ctx, kid)
}

// A box sends its roster when it changes, not again: an approval the keys
// part could not take at once is tried again without a new roster.
func TestApprovalOutlastsAKeysPartThatIsAway(t *testing.T) {
	old := keepRetry
	keepRetry = 30 * time.Millisecond
	t.Cleanup(func() { keepRetry = old })
	g := newRig(t)
	flaky := &flakyKeys{AgentKeys: g.keys, down: 3}
	g.s.keys = flaky
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	if ev := next(t, ch); ev.name != "approved" {
		t.Fatalf("event %q", ev.name)
	}
}
