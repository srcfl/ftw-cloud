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
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"html"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
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
	// Every test client lives on example.com.
	g.s.fetch.hostBurst, g.s.fetch.hostRate = 1e4, 1e4
	g.s.fetch.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, g.cimd.Listener.Addr().String())
	}
	// One test client is one address: its own limits are looser than a
	// stranger's, and TestLimitsPerAddress checks those.
	g.s.authorizeByIP, g.s.registerByIP, g.s.lookupByIP = newIPLimiter(1e4, 1e4), newIPLimiter(1e4, 1e4), newIPLimiter(1e4, 1e4)
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
	g.settle()
}

// settle waits until Run has applied what is pending.
func (g *rig) settle() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		g.s.pmu.Lock()
		n := len(g.s.pending)
		g.s.pmu.Unlock()
		if n == 0 && g.s.busy.Load() == 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
}

// agentDevice is an agent row as the box lists it in its roster, for the
// metadata-document client, ending in 30 days.
func agentDevice(key []byte, scopes ...string) cloudwire.Device {
	return agentFor(key, cimdID, time.Now().Add(30*24*time.Hour), scopes...)
}

// agentFor is an agent row for a client, with the end the box set. Its
// copy scopes are empty and it has no tunnel of its own, as the contract
// has it for agents.
func agentFor(key []byte, clientID string, end time.Time, scopes ...string) cloudwire.Device {
	var ops []string
	for op, sc := range protocol.RegistryAgentOps {
		if slices.Contains(scopes, sc) {
			ops = append(ops, op)
		}
	}
	slices.Sort(ops)
	return cloudwire.Device{ID: cloudwire.DeviceID(key), Key: key, Role: protocol.RoleAgent, Scopes: []string{}, Epoch: 1,
		Agent: &cloudwire.Agent{Scopes: scopes, Ops: ops, Caps: protocol.Caps{HoldS: 600, MaxW: 5000, PerMin: 6},
			ExpiresAtMs: end.UnixMilli(), Principal: protocol.Principal{Client: "Claude", ClientID: clientID}}}
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
	g.roster(home, agentFor(f.agentKey(g.t), clientID, g.now().Add(30*24*time.Hour), scopes...))
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
	if f.view.Client.Name != "Claude" || f.view.Client.Verified || f.view.Client.Host != "example.com" ||
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
	g.advance(refreshGrace + time.Second)
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
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {f.verifier},
		"redirect_uri": {cimdBack}}
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
		if back := backLink(t, resp); back.Query().Get("error") != "invalid_request" || back.Query().Get("iss") != Issuer {
			t.Fatalf("without S256 PKCE: %s", back)
		}
	}

	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	wrong, _ := pkce()
	if status, _ := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {wrong},
		"redirect_uri": {cimdBack}}); status != http.StatusBadRequest {
		t.Fatalf("a wrong verifier: %d", status)
	}
}

// backLink is the link an error page offers back to the client, with no
// redirect of its own.
func backLink(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`<a class="button" href="([^"]+)">Go back to `).FindSubmatch(body)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || m == nil {
		t.Fatalf("not an error page with a link back: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, err := url.Parse(html.UnescapeString(string(m[1])))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// Before client and redirect URI check out, nothing redirects. After, an
// error goes back with iss: at once for a client FTW Cloud knows, and by a
// link the person follows for any other (RFC 9700, 4.11.2).
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
	back := backLink(t, resp)
	if back.Query().Get("error") != "invalid_target" || back.Query().Get("iss") != Issuer || back.Host != "example.com" {
		t.Fatalf("another resource: %s", back)
	}
	q.Set("resource", Resource)
	q.Set("scope", "ftw.live.read admin")
	resp, _ = noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	if back := backLink(t, resp); back.Query().Get("error") != "invalid_scope" {
		t.Fatalf("an unknown scope: %s", back)
	}
	// A client FTW Cloud knows goes back at once.
	old := verifiedClients
	verifiedClients = append(slices.Clone(old), cimdID)
	t.Cleanup(func() { verifiedClients = old })
	resp, _ = noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("iss") != Issuer {
		t.Fatalf("a known client's error: %d %s", resp.StatusCode, loc)
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
	g.roster(home, agentFor(f.agentKey(t), id, time.Now().Add(time.Hour), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	stop()
	if status, tk := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {id}, "code_verifier": {f.verifier},
		"redirect_uri": {"https://grok.example/cb"}}); status != http.StatusOK {
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
	g.roster(home, agentFor(f.agentKey(t), cid, time.Now().Add(time.Hour), ScopeLiveRead))
	code = redirectOf(t, next(t, ch)).Query().Get("code")
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cid}, "code_verifier": {f.verifier},
		"redirect_uri": {"https://chatgpt.com/connector_platform_oauth_redirect"}}
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
// that started it gets the code, or keeps a stream open.
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
	if _, open := <-stranger; open {
		t.Fatal("a stranger's stream stayed open")
	}
	// Another key; the right key under another id, for another client,
	// past its end, as support, or as a phone: none of them approves.
	other := bytes.Repeat([]byte{1}, 32)
	key := f.agentKey(t)
	wrongID := agentDevice(key, ScopeLiveRead)
	wrongID.ID = "someone"
	otherClient := agentFor(key, "https://evil.example/client.json", time.Now().Add(time.Hour), ScopeLiveRead)
	ended := agentFor(key, cimdID, g.now().Add(-time.Second), ScopeLiveRead)
	support := agentDevice(key, ScopeLiveRead)
	support.Role = protocol.RoleSupport
	phone := agentDevice(key, ScopeLiveRead)
	phone.Agent = nil
	for _, d := range []cloudwire.Device{wrongID, otherClient, ended, support, phone} {
		g.roster(home, agentDevice(other, ScopeLiveRead), d)
	}
	select {
	case ev := <-browser:
		t.Fatalf("event %q before the roster listed the agent", ev.name)
	case <-time.After(100 * time.Millisecond):
	}
	if g.details(f.rid).Status != statusPending {
		t.Fatal("approved without the agent in the roster")
	}

	g.roster(home, agentDevice(key, ScopeLiveRead))
	stranger, stop3 := g.events(f, false)
	defer stop3()
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
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentFor(f.agentKey(t), cimdID, g.now().Add(2*time.Hour), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	_, tk := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {f.verifier},
		"redirect_uri": {cimdBack}})
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
	other := "ftwat_" + home + "." + randomToken(32)
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
	if v.Agent.Key != f.view.Agent.Key || v.Request != "" || v.Offer == "" || v.Offer != f.view.Offer {
		t.Fatalf("by code: %+v", v)
	}
	// Once.
	if resp, _ := http.Get(g.srv.URL + "/oauth/requests?code=" + f.view.Code); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("a code used twice: %d", resp.StatusCode)
	}
	resp, _ := http.Get(g.srv.URL + "/oauth/requests?code=ZZZZZZ")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unknown code: %d", resp.StatusCode)
	}
	// The box's page reads a refusal too, so it can tell a wrong code from
	// no network.
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("an unknown code's answer is not readable from the box's page: %q", got)
	}
	// Lookups are rate limited for everyone together.
	limited := false
	for range 60 {
		resp, _ := http.Get(g.srv.URL + "/oauth/requests?code=ZZZZZZ")
		if resp.StatusCode == http.StatusTooManyRequests {
			if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
				t.Fatal("a limited lookup's answer is not readable from the box's page")
			}
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
	for _, want := range []string{"Let Claude into your home?", "From example.com. FTW Cloud does not know this client", "127.0.0.1:8123",
		"a program on this computer", "<svg", AppLink, scopeWords[ScopeDispatchHold], "Control lasts minutes",
		// The QR code or the link opens the app; the code is for an owner
		// who has neither, in the app or on the box's own page.
		"scan the QR code with your phone, or open the link", "Type this code in the FTW app, or on your box's own page under Settings, then Access",
		"in the FTW app or on your box"} {
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
// for everyone together, since each request makes a key, and the limit
// comes before the client's document is fetched.
func TestAuthorizeIsRateLimited(t *testing.T) {
	g := newRig(t)
	var hits atomic.Int32
	inner := g.cimd.Config.Handler
	g.cimd.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		inner.ServeHTTP(w, r)
	})
	limited := false
	for i := range 40 {
		// A new document each time, so the cache does not hide a fetch.
		id := fmt.Sprintf("https://example.com/oauth/c%d.json", i)
		g.docsMu.Lock()
		g.docs[fmt.Sprintf("/oauth/c%d.json", i)] = `{"client_id":"` + id + `","client_name":"C","redirect_uris":["` + cimdBack + `"]}`
		g.docsMu.Unlock()
		q, _ := g.authorizeParams(id, cimdBack, "")
		before := hits.Load()
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
		if resp.StatusCode == http.StatusTooManyRequests {
			if hits.Load() != before {
				t.Fatal("a limited request fetched a document")
			}
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("authorize is not limited")
	}
}

// One address cannot spend everyone's bucket: authorize, registration and
// code lookups each have one per address, an IPv6 address by its /64.
func TestLimitsPerAddress(t *testing.T) {
	g := newRig(t)
	g.s.authorizeByIP, g.s.registerByIP, g.s.lookupByIP = newIPLimiter(3, 0.001), newIPLimiter(2, 0.001), newIPLimiter(5, 0.001)
	mux := http.NewServeMux()
	g.s.Mount(mux)
	do := func(addr, target string) int {
		method := http.MethodGet
		if strings.HasPrefix(target, "/oauth/register") {
			method = http.MethodPost
		}
		r := httptest.NewRequest(method, target, strings.NewReader(`{"redirect_uris":["https://x.example/cb"]}`))
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w.Code
	}
	q, _ := g.authorizeParams(cimdID, cimdBack, "")
	for name, c := range map[string]struct {
		target string
		n      int
	}{
		"authorize": {"/oauth/authorize?" + q.Encode(), 3},
		"register":  {"/oauth/register", 2},
		"lookup":    {"/oauth/requests?code=AAAA-AAAA", 5},
	} {
		for i := range c.n {
			if code := do("198.51.100.7:4000", c.target); code == http.StatusTooManyRequests {
				t.Fatalf("%s: limited after %d", name, i)
			}
		}
		if code := do("198.51.100.7:4001", c.target); code != http.StatusTooManyRequests {
			t.Fatalf("%s: not limited per address: %d", name, code)
		}
		if code := do("[2001:db8:1:2::9]:4000", c.target); code == http.StatusTooManyRequests {
			t.Fatalf("%s: another address was limited", name)
		}
		for range c.n - 1 {
			do("[2001:db8:1:2::a]:4000", c.target)
		}
		if code := do("[2001:db8:1:2:ffff::1]:4000", c.target); code != http.StatusTooManyRequests {
			t.Fatalf("%s: one /64 counts as many callers: %d", name, code)
		}
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

// The offer: the contract's SignedOffer, which protocol.OpenOffer opens
// with the offer key pinned by its kid. It carries the agent's key, the
// client and its host, what it asks for, the code and an end within ten
// minutes, and no home; in the QR, the link and the request's details alike.
func TestTheOfferIsSignedAndCarriesTheConsent(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead+" "+ScopeDispatchHold)
	raw, err := base64.RawURLEncoding.DecodeString(f.view.Offer)
	if err != nil {
		t.Fatal(err)
	}
	var so protocol.SignedOffer
	if err := cbor.Unmarshal(raw, &so); err != nil {
		t.Fatal(err)
	}
	pub, _ := g.keys.OfferKey(context.Background())
	o, err := protocol.OpenOffer(map[string][]byte{keys.OfferKid(pub): pub}, so, g.now().UnixMilli())
	if err != nil {
		t.Fatalf("the offer does not open: %v", err)
	}
	if o.Home != "" || !bytes.Equal(o.Key, f.agentKey(t)) || o.Role != protocol.RoleAgent || o.Client != "Claude" ||
		o.ClientID != cimdID || o.ClientHost != "example.com" || o.Verified || o.Code != f.view.Code ||
		!slices.Equal(o.Scopes, []string{ScopeDispatchHold, ScopeLiveRead}) || !slices.Equal(o.Ops, []string{"loadpoint.hold"}) ||
		o.Caps.HoldS == 0 || o.TTLS != uint64(protocol.AgentMaxMs/1000) || o.ExpMs > g.now().UnixMilli()+protocol.OfferTTLMs {
		t.Fatalf("offer %+v", o)
	}
	// Another key does not open it, and it ends.
	if _, err := protocol.OpenOffer(map[string][]byte{keys.OfferKid(pub): bytes.Repeat([]byte{4}, 65)}, so, g.now().UnixMilli()); err == nil {
		t.Fatal("an offer opened with another key")
	}
	if _, err := protocol.OpenOffer(map[string][]byte{keys.OfferKid(pub): pub}, so, o.ExpMs); err == nil {
		t.Fatal("an offer opened at its end")
	}
	// The page's link and QR carry the same offer, in the fragment.
	q, _ := g.authorizeParams(cimdID, cimdBack, "")
	resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	page, _ := io.ReadAll(resp.Body)
	if !regexp.MustCompile(`href="https://app\.ftw\.energy/a#[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{200,}"`).Match(page) {
		t.Fatal("the app link does not carry the request and the offer in its fragment")
	}
	// A registered client is shown by its redirect URI's host.
	resp2, _ := http.Post(g.srv.URL+"/oauth/register", "application/json", strings.NewReader(`{"client_name":"X","redirect_uris":["https://x.example/cb"]}`))
	var reg map[string]any
	_ = json.NewDecoder(resp2.Body).Decode(&reg)
	f2 := g.start(reg["client_id"].(string), "https://x.example/cb", "")
	if f2.view.Client.Host != "x.example" {
		t.Fatalf("a registered client's host: %q", f2.view.Client.Host)
	}
}

func TestTheOfferKeyIsPublished(t *testing.T) {
	g := newRig(t)
	var v struct{ Alg, Tag, Kid, Pub string }
	getJSON(t, g.srv.URL+"/.well-known/ftw-offer-key", &v)
	pub, _ := g.keys.OfferKey(context.Background())
	// The kid is the contract's, so Core's pin list takes it as it comes.
	if keys.OfferKid(pub) != protocol.OfferKid(pub) {
		t.Fatal("the keys part's kid is not the contract's")
	}
	if v.Alg != "ES256" || v.Tag != protocol.OfferTag || v.Kid != keys.OfferKid(pub) || v.Pub != base64.RawURLEncoding.EncodeToString(pub) {
		t.Fatalf("offer key %+v", v)
	}
}

// A token is routed to its home, so any instance can tell where it belongs,
// but it shows no id a client could link across tokens: the home is sealed
// with a fresh nonce each time. The route proves nothing by itself.
func TestTokensRouteToTheirHomeWithoutNamingIt(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	for _, tok := range []string{tk.Access, tk.Refresh} {
		if h, ok := g.s.TokenHome(tok); !ok || h != home {
			t.Fatalf("token %s routes to %q", tok, h)
		}
		if strings.Contains(tok, home) {
			t.Fatalf("token %s names its home", tok)
		}
	}
	route := func(tok string) string { r, _, _ := strings.Cut(tok[len(accessPrefix):], "."); return r }
	if route(tk.Access) == route(tk.Refresh) {
		t.Fatal("two tokens share a route")
	}
	// A route made with another key, or edited, does not open.
	other, _ := loadRouteKey(filepath.Join(t.TempDir(), "k"))
	if _, ok := g.s.TokenHome(other.newToken(accessPrefix, home)); ok {
		t.Fatal("a route under another key opened")
	}
	forged := g.s.route.newToken(accessPrefix, home)
	if _, aerr := g.bearer(forged); aerr == nil {
		t.Fatal("a token with a good route and a made-up secret was accepted")
	}
}

// The grant is what the token carries and the newest roster still lists:
// an owner who narrows it narrows the token at once, wider rights need a new
// consent, a renewal extends the agent, and an end reached by the service's
// own clock stops it without a roster.
func TestTheGrantFollowsTheRoster(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead+" "+ScopePlanRead)
	tk := g.approve(f, cimdID, ScopeLiveRead, ScopePlanRead)
	key := f.agentKey(t)
	g.roster(home, agentFor(key, cimdID, g.now().Add(time.Hour), ScopeLiveRead))
	grant, aerr := g.bearer(tk.Access)
	if aerr != nil || grant.Has(ScopePlanRead) || !grant.Has(ScopeLiveRead) || grant.Caps.MaxW != 5000 {
		t.Fatalf("after narrowing: %+v %v", grant, aerr)
	}
	g.roster(home, agentFor(key, cimdID, g.now().Add(3*time.Hour), ScopeLiveRead, ScopePlanRead, ScopeDispatchHold))
	grant, _ = g.bearer(tk.Access)
	if grant.Has(ScopeDispatchHold) || !grant.Has(ScopePlanRead) || !slices.Contains(grant.Ops, "loadpoint.hold") ||
		grant.AgentExpires.Before(g.now().Add(2*time.Hour)) {
		t.Fatalf("after widening and renewing: %+v", grant)
	}
	g.advance(3*time.Hour + time.Second)
	if _, aerr := g.bearer(tk.Access); aerr == nil {
		t.Fatal("an agent past its end was admitted")
	}
}

// A refresh that narrows the scope narrows what the new token allows.
func TestARefreshCanNarrow(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeLiveRead+" "+ScopePlanRead)
	tk := g.approve(f, cimdID, ScopeLiveRead, ScopePlanRead)
	status, tk2 := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}, "scope": {ScopeLiveRead}})
	if status != http.StatusOK {
		t.Fatalf("refresh: %d", status)
	}
	grant, aerr := g.bearer(tk2.Access)
	if aerr != nil || grant.Has(ScopePlanRead) || !grant.Has(ScopeLiveRead) {
		t.Fatalf("a narrowed token: %+v %v", grant, aerr)
	}
}

func TestTokenShape(t *testing.T) {
	k, _ := loadRouteKey(filepath.Join(t.TempDir(), "k"))
	good := k.newToken(accessPrefix, home)
	if !tokenShape(good, accessPrefix) {
		t.Fatal("a token this server makes")
	}
	for _, bad := range []string{"", good + "x", strings.Replace(good, ".", "", 1), k.newToken(refreshPrefix, home),
		accessPrefix + home + "." + randomToken(32), strings.Replace(good, ".", "!.", 1),
		accessPrefix + strings.Repeat("a", 60) + "." + strings.Repeat("!", 43), "ftwat_" + strings.Repeat("a", 5000)} {
		if tokenShape(bad, accessPrefix) {
			t.Errorf("%q passed", bad)
		}
	}
}

// Only clients FTW Cloud knows, by the exact URL of their document, are
// verified: not another document on the same host, and not a host that
// merely ends like it.
func TestVerifiedClients(t *testing.T) {
	for id, want := range map[string]bool{
		"https://claude.ai/oauth/mcp-oauth-client-metadata":              true,
		"https://claude.ai/oauth/mcp-oauth-client-metadata/":             false,
		"https://claude.ai/other":                                        false,
		"https://www.claude.ai/oauth/mcp-oauth-client-metadata":          false,
		"https://evilclaude.ai/oauth/mcp-oauth-client-metadata":          false,
		"https://claude.ai.evil.example/oauth/mcp-oauth-client-metadata": false,
		"https://chatgpt.com/oauth/client.json":                          false,
	} {
		if verifiedClient(id) != want {
			t.Errorf("%s: %v", id, !want)
		}
	}
}
