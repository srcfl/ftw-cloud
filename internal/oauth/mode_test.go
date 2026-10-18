package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startUnchosen follows the actual omitted-scope page without choosing yet.
func (g *rig) startUnchosen() (*flow, string) {
	g.t.Helper()
	q, f := g.authorizeParams(cimdID, cimdBack, "")
	resp, err := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		g.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := ridRE.FindSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		g.t.Fatalf("start mode: %d %s", resp.StatusCode, body)
	}
	f.rid = string(m[1])
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName(f.rid) {
			f.cookie = cookie
		}
	}
	if f.cookie == nil {
		g.t.Fatal("no original browser cookie")
	}
	return f, string(body)
}

func (g *rig) modeRequest(f *flow, mode, origin string, cookie bool) *http.Response {
	g.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, g.srv.URL+"/oauth/requests/"+f.rid+"/mode", strings.NewReader(`{"mode":"`+mode+`"}`))
	req.Header.Set("Origin", origin)
	if cookie {
		req.AddCookie(f.cookie)
	}
	resp, err := noFollow.Do(req)
	if err != nil {
		g.t.Fatal(err)
	}
	return resp
}

func (g *rig) modeConsent(f *flow) consent {
	g.t.Helper()
	c, ok, err := g.s.st.consentByRID(f.rid)
	if err != nil || !ok {
		g.t.Fatal("missing consent", err)
	}
	return c
}

func TestModeChoiceHidesAndBlocksApprovalUntilSaved(t *testing.T) {
	g := newRig(t)
	f, page := g.startUnchosen()
	c := g.modeConsent(f)
	if c.Scope != "" || c.Offer != "" || !strings.Contains(page, "Read and troubleshoot") ||
		!strings.Contains(page, "Set up and configure") || strings.Contains(page, "<svg") ||
		strings.Contains(page, c.Code) || strings.Contains(page, showCode(c.Code)) {
		t.Fatal("initial mode page exposed an offer or code")
	}
	resp, _ := http.Get(g.srv.URL + "/oauth/requests/" + f.rid)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || strings.Contains(string(body), "agent") || strings.Contains(string(body), "offer") ||
		!strings.Contains(string(body), "mode_required") {
		t.Fatalf("unselected public view: %d %s", resp.StatusCode, body)
	}
	if _, found, err := g.s.st.spendCode(c.Code, g.now()); err != nil || found {
		t.Fatal("unselected code spent", found, err)
	}
	if _, _, found, err := g.s.st.pendingByKey(c.AgentKey, g.now()); err != nil || found {
		t.Fatal("unselected key ready for approval", found, err)
	}
	g.roster(home, agentDevice(c.AgentKey, ReadScopes...))
	if g.modeConsent(f).Status != statusPending {
		t.Fatal("roster approved before mode choice")
	}
	if err := g.s.st.approve(hash(f.rid), c, agentGrant{}, g.now()); err != errGone {
		t.Fatal("final approval accepted unselected phase", err)
	}
	var claims atomic.Int32
	g.s.ClaimInvite = func(context.Context, InviteClaim) error { claims.Add(1); return nil }
	req, _ := http.NewRequest(http.MethodPost, g.srv.URL+"/oauth/requests/"+f.rid+"/invite", strings.NewReader(`{"code":"K7M-4PX"}`))
	req.Header.Set("Origin", Issuer)
	req.AddCookie(f.cookie)
	resp, _ = noFollow.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict || claims.Load() != 0 {
		t.Fatal("invitation reached the box before mode choice")
	}
	resp = g.modeRequest(f, "setup", Issuer, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("setup mode", resp.StatusCode)
	}
	chosen := g.modeConsent(f)
	want := append(slices.Clone(ReadScopes), ScopeSetupWrite)
	if chosen.Offer == "" || !slices.Equal(splitScope(chosen.Scope), want) || chosen.Kid != c.Kid ||
		!slices.Equal(chosen.AgentKey, c.AgentKey) || !chosen.Expires.Equal(c.Expires) {
		t.Fatal("mode changed the key/deadline or lost setup rights")
	}
	// A lost mode reply can be retried without a new key, offer or deadline.
	resp = g.modeRequest(f, "setup", Issuer, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || g.modeConsent(f).Offer != chosen.Offer {
		t.Fatal("same mode did not recover its receipt")
	}
	f.view = g.details(f.rid)
	tokens := g.approve(f, cimdID, want...)
	grant, err := g.bearer(tokens.Access)
	if err != nil || !grant.Has(ScopeSetupWrite) || !grant.Has(ScopeDiagRun) {
		t.Fatal("setup connection cannot both read and write", err)
	}
}

type heldModeKeys struct {
	AgentKeys
	entered chan struct{}
	release chan struct{}
}

func (k *heldModeKeys) SignOffer(ctx context.Context, kid string, offer []byte) ([]byte, error) {
	sig, err := k.AgentKeys.SignOffer(ctx, kid, offer)
	if err != nil {
		return nil, err
	}
	k.entered <- struct{}{}
	select {
	case <-k.release:
		return sig, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func modeEntered(t *testing.T, keys *heldModeKeys) {
	t.Helper()
	select {
	case <-keys.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("mode did not reach signer")
	}
}

func TestModeConcurrentChoicesKeepOnlyTheSavedOffer(t *testing.T) {
	g := newRig(t)
	k := &heldModeKeys{AgentKeys: g.keys, entered: make(chan struct{}, 2), release: make(chan struct{})}
	g.s.keys = k
	f, _ := g.startUnchosen()
	done := make(chan *http.Response, 2)
	for _, mode := range []string{"read", "setup"} {
		go func(mode string) { done <- g.modeRequest(f, mode, Issuer, true) }(mode)
	}
	modeEntered(t, k)
	modeEntered(t, k)
	close(k.release)
	var statuses []int
	for range 2 {
		resp := <-done
		statuses = append(statuses, resp.StatusCode)
		var receipt map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&receipt)
		resp.Body.Close()
		if receipt["connect"] != "/oauth/requests/"+f.rid+"/connect" {
			t.Fatal("missing link to saved choice", receipt)
		}
	}
	slices.Sort(statuses)
	if !slices.Equal(statuses, []int{http.StatusOK, http.StatusConflict}) || g.modeConsent(f).Offer == "" {
		t.Fatal("two different choices both won", statuses)
	}
}

func TestModeCannotReviveCancelledOrExpiredRequestAfterSigning(t *testing.T) {
	for _, cancel := range []bool{true, false} {
		t.Run(map[bool]string{true: "cancelled", false: "expired"}[cancel], func(t *testing.T) {
			g := newRig(t)
			k := &heldModeKeys{AgentKeys: g.keys, entered: make(chan struct{}, 1), release: make(chan struct{})}
			g.s.keys = k
			f, _ := g.startUnchosen()
			done := make(chan *http.Response, 1)
			go func() { done <- g.modeRequest(f, "setup", Issuer, true) }()
			modeEntered(t, k)
			if cancel {
				if _, ok, err := g.s.st.deny(f.rid, g.now()); err != nil || !ok {
					t.Fatal("deny", ok, err)
				}
			} else {
				g.advance(RequestTTL + time.Second)
			}
			close(k.release)
			resp := <-done
			resp.Body.Close()
			if resp.StatusCode != http.StatusGone || g.modeConsent(f).Offer != "" || g.modeConsent(f).Scope != "" {
				t.Fatal("late signer revived request", resp.StatusCode)
			}
		})
	}
}

func TestModeSameChoiceResumesAfterApprovalDuringSigning(t *testing.T) {
	g := newRig(t)
	k := &heldModeKeys{AgentKeys: g.keys, entered: make(chan struct{}, 2), release: make(chan struct{})}
	g.s.keys = k
	f, _ := g.startUnchosen()
	done := make(chan *http.Response, 2)
	for range 2 {
		go func() { done <- g.modeRequest(f, "setup", Issuer, true) }()
	}
	modeEntered(t, k)
	modeEntered(t, k)
	k.release <- struct{}{} // Only the first answer arrives before approval.
	first := <-done
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatal("first choice", first.StatusCode)
	}
	f.view = g.details(f.rid)
	scopes := append(slices.Clone(ReadScopes), ScopeSetupWrite)
	g.approve(f, cimdID, scopes...)
	close(k.release)
	late := <-done
	late.Body.Close()
	if late.StatusCode != http.StatusOK {
		t.Fatal("same saved choice could not resume after approval", late.StatusCode)
	}
	for mode, want := range map[string]int{"setup": http.StatusOK, "read": http.StatusConflict} {
		resp := g.modeRequest(f, mode, Issuer, true)
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatal("approved choice retry", mode, resp.StatusCode)
		}
	}
}

func TestModeSigningUsesAuthorizationBudgetButSavedRetryDoesNot(t *testing.T) {
	for _, budget := range []string{"global", "address"} {
		t.Run(budget, func(t *testing.T) {
			g := newRig(t)
			k := &heldModeKeys{AgentKeys: g.keys, entered: make(chan struct{}, 2), release: make(chan struct{})}
			g.s.keys = k
			f, _ := g.startUnchosen()
			if budget == "global" {
				g.s.authorizeLimit = newLimiter(1, 0)
			} else {
				g.s.authorizeByIP = newIPLimiter(1, 0)
			}
			done := make(chan *http.Response, 1)
			go func() { done <- g.modeRequest(f, "read", Issuer, true) }()
			modeEntered(t, k)
			limited := g.modeRequest(f, "setup", Issuer, true)
			limited.Body.Close()
			if limited.StatusCode != http.StatusTooManyRequests {
				t.Fatal("unbudgeted signing", limited.StatusCode)
			}
			close(k.release)
			first := <-done
			first.Body.Close()
			if first.StatusCode != http.StatusOK {
				t.Fatal("budgeted choice failed", first.StatusCode)
			}
			retry := g.modeRequest(f, "read", Issuer, true)
			retry.Body.Close()
			if retry.StatusCode != http.StatusOK || len(k.entered) != 0 {
				t.Fatal("saved retry signed again", retry.StatusCode)
			}
		})
	}
}

func TestModeRequiresOriginalBrowserAndExactOrigin(t *testing.T) {
	g := newRig(t)
	f, _ := g.startUnchosen()
	for _, tc := range []struct {
		origin string
		cookie bool
	}{{"", true}, {"https://evil.example", true}, {Issuer, false}} {
		resp := g.modeRequest(f, "setup", tc.origin, tc.cookie)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || g.modeConsent(f).Offer != "" {
			t.Fatal("mode accepted another browser/origin", resp.StatusCode)
		}
	}
	resp, _ := http.Get(g.srv.URL + "/oauth/requests/" + f.rid + "/connect")
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("connect view without cookie", resp.StatusCode)
	}
	f.rid = "x"
	resp = g.modeRequest(f, "setup", Issuer, true)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("short rid", resp.StatusCode)
	}
}

func TestExplicitScopesNeverBecomeSetupByChoosingMode(t *testing.T) {
	for _, scope := range []string{"", "offline_access", ScopeLiveRead} {
		t.Run(scope, func(t *testing.T) {
			g := newRig(t)
			q, f := g.authorizeParams(cimdID, cimdBack, scope)
			q.Set("scope", scope) // Even an explicitly blank parameter is explicit.
			resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			m := ridRE.FindSubmatch(body)
			if resp.StatusCode != http.StatusOK || m == nil || strings.Contains(string(body), `id="mode-form"`) {
				t.Fatal("explicit scope got a mode choice")
			}
			f.rid = string(m[1])
			for _, ck := range resp.Cookies() {
				if ck.Name == cookieName(f.rid) {
					f.cookie = ck
				}
			}
			before := g.modeConsent(f)
			resp = g.modeRequest(f, "setup", Issuer, true)
			resp.Body.Close()
			after := g.modeConsent(f)
			if resp.StatusCode != http.StatusConflict || after.Scope != before.Scope || after.Offer != before.Offer || slices.Contains(splitScope(after.Scope), ScopeSetupWrite) {
				t.Fatal("explicit scope widened", resp.StatusCode)
			}
		})
	}
}
