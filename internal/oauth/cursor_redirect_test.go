package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Cursor's desktop callback is the one custom-scheme redirect URI, and only
// byte for byte.
func TestOnlyTheExactCursorRedirectPasses(t *testing.T) {
	if err := checkRedirect(cursorRedirect); err != nil {
		t.Fatalf("%s: %v", cursorRedirect, err)
	}
	for _, bad := range []string{
		"cursor://anysphere.cursor-mcp/oauth/callback/",
		"cursor://anysphere.cursor-mcp/oauth/callback?x=1",
		"cursor://anysphere.cursor-mcp/oauth/callback?",
		"cursor://anysphere.cursor-mcp/oauth/callback#",
		"cursor://anysphere.cursor-mcp/oauth/callback#x",
		"cursor://anysphere.cursor-mcp/oauth/callbackx",
		"cursor://anysphere.cursor-mcp/oauth/callback/../callback",
		"cursor://anysphere.cursor-mcp/oauth/other",
		"cursor://anysphere.cursor-mcp/",
		"cursor://anysphere.cursor-mcp",
		"cursor://anysphere.cursor-mcp:443/oauth/callback",
		"cursor://user@anysphere.cursor-mcp/oauth/callback",
		"cursor://anysphere.cursor-mcp.evil/oauth/callback",
		"cursor://evil.anysphere.cursor-mcp/oauth/callback",
		"cursor://evil/oauth/callback",
		"cursor://evil",
		"cursor:anysphere.cursor-mcp/oauth/callback",
		"cursor:///oauth/callback",
		"CURSOR://anysphere.cursor-mcp/oauth/callback",
		"Cursor://anysphere.cursor-mcp/oauth/callback",
		"cursor://ANYSPHERE.cursor-mcp/oauth/callback",
		"cursor://anysphere.cursor-mcp/OAuth/callback",
		"cursor://anysphere.cursor-mcp/oauth/callback%20",
		"cursor://anysphere.cursor-mcp/oauth/%63allback",
		" cursor://anysphere.cursor-mcp/oauth/callback",
		"cursor://anysphere.cursor-mcp/oauth/callback ",
		"cursor://anysphere.cursor-mcp/oauth/callback\n",
		"cursor://anysphere.cursor-mcp/oauth/callback\x00",
		"cursor-insiders://anysphere.cursor-mcp/oauth/callback",
		"vscode://anysphere.cursor-mcp/oauth/callback",
		"myapp://cb",
		"javascript:alert(1)//cursor://anysphere.cursor-mcp/oauth/callback",
		"javascript://anysphere.cursor-mcp/oauth/callback",
		"data:text/html,cursor://anysphere.cursor-mcp/oauth/callback",
		"file://anysphere.cursor-mcp/oauth/callback",
		"http://anysphere.cursor-mcp/oauth/callback",
	} {
		if checkRedirect(bad) == nil {
			t.Errorf("%q passes", bad)
		}
	}
	// The https and loopback rules stand.
	for _, ok := range []string{"https://chatgpt.com/cb", "http://127.0.0.1:53121/cb", "http://localhost/cb"} {
		if err := checkRedirect(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

// A client registers the Cursor callback by dynamic registration, gets a
// code there only for that exact URI, and still needs PKCE S256 and the
// same redirect URI at the token endpoint.
func TestCursorRegistersAndSignsInWithItsCallback(t *testing.T) {
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
		`{"redirect_uris":["cursor://evil/oauth/callback"]}`,
		`{"redirect_uris":["cursor://anysphere.cursor-mcp/oauth/callback?x=1"]}`,
		`{"redirect_uris":["CURSOR://anysphere.cursor-mcp/oauth/callback"]}`,
		`{"redirect_uris":["` + cursorRedirect + `","myapp://cb"]}`,
	} {
		if status, out := register(bad); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %v", bad, status, out)
		}
	}
	status, out := register(`{"client_name":"Cursor","redirect_uris":["` + cursorRedirect + `"]}`)
	if status != http.StatusCreated {
		t.Fatalf("registration: %d %v", status, out)
	}
	id := out["client_id"].(string)
	if uris, _ := out["redirect_uris"].([]any); len(uris) != 1 || uris[0] != cursorRedirect {
		t.Fatalf("registered redirect_uris: %v", out["redirect_uris"])
	}

	// /authorize takes only the registered URI, byte for byte, and nothing
	// redirects before it checks out.
	for _, r := range []string{
		"cursor://anysphere.cursor-mcp/oauth/callback/",
		"cursor://anysphere.cursor-mcp/oauth/callback?x=1",
		"cursor://evil/oauth/callback",
		"Cursor://anysphere.cursor-mcp/oauth/callback",
		"https://evil.example/cb",
	} {
		q, _ := g.authorizeParams(id, r, "")
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
		if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
			t.Fatalf("%s: %d %q", r, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// A client registered with an https URI cannot use the Cursor one.
	_, other := register(`{"client_name":"Other","redirect_uris":["https://grok.example/cb"]}`)
	q, _ := g.authorizeParams(other["client_id"].(string), cursorRedirect, "")
	if resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode()); resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("another client's redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// PKCE S256 is still required: plain and missing are refused, with
	// the error offered back as a link to the exact callback.
	for _, mod := range []func(url.Values){
		func(q url.Values) { q.Set("code_challenge_method", "plain") },
		func(q url.Values) { q.Del("code_challenge_method") },
		func(q url.Values) { q.Del("code_challenge") },
	} {
		q, _ := g.authorizeParams(id, cursorRedirect, "")
		mod(q)
		resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
		if resp.StatusCode == http.StatusOK || resp.Header.Get("Location") != "" {
			t.Fatalf("without S256: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), `href="cursor://anysphere.cursor-mcp/oauth/callback?`) {
			t.Fatalf("the error page has no working link back to Cursor: %s", body)
		}
	}

	// The owner is told it goes back to a program on this computer.
	q, _ = g.authorizeParams(id, cursorRedirect, ScopeLiveRead)
	resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "<strong>cursor://anysphere.cursor-mcp</strong>") ||
		!strings.Contains(string(page), "That is a program on this computer") {
		t.Fatalf("consent page: %d %s", resp.StatusCode, page)
	}
	f := g.start(id, cursorRedirect, "")
	if f.view.Redirect.Host != "anysphere.cursor-mcp" || !f.view.Redirect.Local {
		t.Fatalf("redirect shown as %+v", f.view.Redirect)
	}
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentFor(f.agentKey(t), id, time.Now().Add(time.Hour), ScopeLiveRead))
	back := redirectOf(t, next(t, ch))
	code := back.Query().Get("code")
	if back.Scheme != "cursor" || back.Host != "anysphere.cursor-mcp" || back.Path != "/oauth/callback" ||
		code == "" || back.Query().Get("state") != f.state || back.Query().Get("iss") != Issuer {
		t.Fatalf("redirect: %s", back)
	}
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {id}, "code_verifier": {f.verifier},
		"redirect_uri": {cursorRedirect + "/"}}
	if status, tk := g.token(form); status != http.StatusBadRequest {
		t.Fatalf("token with another redirect_uri: %d %+v", status, tk)
	}
}

// The code goes only to whoever holds the PKCE verifier, and with it the
// swap works.
func TestACursorCodeNeedsItsVerifier(t *testing.T) {
	for _, right := range []bool{false, true} {
		g := newRig(t)
		resp, err := http.Post(g.srv.URL+"/oauth/register", "application/json",
			strings.NewReader(`{"client_name":"Cursor","redirect_uris":["`+cursorRedirect+`"]}`))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		id := out["client_id"].(string)

		f := g.start(id, cursorRedirect, "")
		ch, stop := g.events(f, true)
		next(t, ch)
		g.roster(home, agentFor(f.agentKey(t), id, time.Now().Add(time.Hour), ScopeLiveRead))
		code := redirectOf(t, next(t, ch)).Query().Get("code")
		stop()
		verifier, _ := pkce()
		if right {
			verifier = f.verifier
		}
		status, tk := g.token(url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {id},
			"code_verifier": {verifier}, "redirect_uri": {cursorRedirect}})
		if right != (status == http.StatusOK && tk.Access != "") {
			t.Fatalf("right verifier %v: %d %+v", right, status, tk)
		}
	}
}
