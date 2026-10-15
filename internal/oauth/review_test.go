package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// pickyKeys is a keys part that will not keep one key, or forget any, for a
// while.
type pickyKeys struct {
	AgentKeys
	mu       sync.Mutex
	keepNot  string
	forgetNo bool
}

func (p *pickyKeys) Keep(ctx context.Context, kid string) error {
	p.mu.Lock()
	refuse := kid == p.keepNot
	p.mu.Unlock()
	if refuse {
		return keys.ErrUnavailable
	}
	return p.AgentKeys.Keep(ctx, kid)
}

func (p *pickyKeys) Forget(ctx context.Context, kid string) error {
	p.mu.Lock()
	refuse := p.forgetNo
	p.mu.Unlock()
	if refuse {
		return keys.ErrUnavailable
	}
	return p.AgentKeys.Forget(ctx, kid)
}

func (p *pickyKeys) set(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

func (g *rig) kidOf(f *flow) string {
	g.t.Helper()
	c, ok, err := g.s.st.consentByRID(f.rid)
	if err != nil || !ok {
		g.t.Fatalf("consent: %v", err)
	}
	return c.Kid
}

// opens reports whether the keys part still holds a kept key.
func (g *rig) opens(kid string) bool {
	box := make([]byte, 32)
	_, _ = rand.Read(box)
	_, _, err := g.keys.Open(context.Background(), kid, box)
	return err == nil
}

// A retry after the keys part was away runs only the approval pass, on the
// newest roster. An older roster is never applied again: it cannot widen a
// grant the owner narrowed since, approve a consent the owner removed, or
// revoke an agent approved since.
func TestARetryRunsOnlyTheApprovalOnTheNewestRoster(t *testing.T) {
	old := keepRetry
	keepRetry = 20 * time.Millisecond
	t.Cleanup(func() { keepRetry = old })
	g := newRig(t)
	a := g.start(cimdID, cimdBack, ScopeLiveRead+" "+ScopePlanRead)
	tk := g.approve(a, cimdID, ScopeLiveRead, ScopePlanRead)
	b := g.start(cimdID, cimdBack, "")
	c := g.start(cimdID, cimdBack, "")
	picky := &pickyKeys{AgentKeys: g.keys, keepNot: g.kidOf(b)}
	g.s.keys = picky
	end := g.now().Add(30 * 24 * time.Hour)

	// The first roster lists A wide and B, whose key cannot be kept yet.
	g.roster(home, agentFor(a.agentKey(t), cimdID, end, ScopeLiveRead, ScopePlanRead), agentFor(b.agentKey(t), cimdID, end, ScopeLiveRead))
	// The owner narrows A, removes B and approves C.
	g.roster(home, agentFor(a.agentKey(t), cimdID, end, ScopeLiveRead), agentFor(c.agentKey(t), cimdID, end, ScopeLiveRead))
	picky.set(func() { picky.keepNot = "" })
	time.Sleep(10 * keepRetry)

	if g.details(b.rid).Status != statusPending {
		t.Fatal("a retry approved a consent the newest roster no longer lists")
	}
	grant, aerr := g.bearer(tk.Access)
	if aerr != nil || grant.Has(ScopePlanRead) {
		t.Fatalf("a retry widened a narrowed grant: %+v %v", grant, aerr)
	}
	if _, ok, _ := g.s.st.agent(home, cloudwire.DeviceID(c.agentKey(t))); !ok {
		t.Fatal("a retry revoked an agent approved since")
	}
}

// Rosters are never dropped: whatever arrives for many homes at once, each
// home's newest roster is applied.
func TestRostersAreNotDropped(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	for i := range 3000 {
		g.s.Roster(fmt.Sprintf("home%05d", i), &cloudwire.Roster{RosterSeq: 1, TTLS: 86400})
	}
	g.s.Roster(home, &cloudwire.Roster{RosterSeq: 1, TTLS: 86400, Devices: []cloudwire.Device{agentDevice(f.agentKey(t), ScopeLiveRead)}})
	if ev := next(t, ch); ev.name != "approved" {
		t.Fatalf("event %q", ev.name)
	}
}

// A home its box purged loses its agents, their tokens and keys, and its
// consents. A roster from before the purge is not applied after it.
func TestAPurgedHomeLosesItsAgents(t *testing.T) {
	g := newRig(t)
	var mu sync.Mutex
	var revoked []string
	g.s.OnRevoke = func(h, agent string) { mu.Lock(); revoked = append(revoked, h+"/"+agent); mu.Unlock() }
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	kid := g.kidOf(f)
	pending := g.start(cimdID, cimdBack, "")

	g.s.Roster(home, &cloudwire.Roster{RosterSeq: 2, TTLS: 86400, Devices: []cloudwire.Device{
		agentDevice(f.agentKey(t), ScopeLiveRead), agentDevice(pending.agentKey(t), ScopeLiveRead)}})
	g.s.DropHome(home)
	g.settle()

	if _, aerr := g.bearer(tk.Access); aerr == nil {
		t.Fatal("a purged home's token works")
	}
	if status, _ := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}}); status != http.StatusBadRequest {
		t.Fatalf("a purged home's refresh token: %d", status)
	}
	if g.opens(kid) {
		t.Fatal("a purged home's agent key still opens")
	}
	if _, ok, _ := g.s.st.consentByRID(f.rid); ok {
		t.Fatal("a purged home's consent is still kept")
	}
	if g.details(pending.rid).Status != statusPending {
		t.Fatal("a roster from before the purge was applied after it")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(revoked) != 1 || revoked[0] != home+"/"+cloudwire.DeviceID(f.agentKey(t)) {
		t.Fatalf("revoked %v", revoked)
	}
}

// A key belongs to one home. A roster that lists, as its agent, a key
// approved for another home revokes it there, forgets the key, and approves
// nothing.
func TestAKeyListedAtASecondHomeIsRevoked(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	kid := g.kidOf(f)
	g.roster("otherhomeotherhomeotherho", agentDevice(f.agentKey(t), ScopeLiveRead))
	if _, aerr := g.bearer(tk.Access); aerr == nil {
		t.Fatal("an agent listed by two homes still works")
	}
	if g.opens(kid) {
		t.Fatal("its key still opens")
	}
	if _, ok, _ := g.s.st.agentByKey(f.agentKey(t)); ok {
		t.Fatal("the second home got the agent")
	}
}

// Revoking always deletes the key: a key the keys part could not forget
// stays queued, across restarts, until it has.
func TestARevokedKeyIsForgottenEvenIfTheKeysPartWasAway(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	g.approve(f, cimdID)
	kid := g.kidOf(f)
	picky := &pickyKeys{AgentKeys: g.keys, forgetNo: true}
	g.s.keys = picky
	g.roster(home) // the owner revoked it
	if !g.opens(kid) {
		t.Fatal("the key went although the keys part refused")
	}
	if q, _ := g.s.st.toForget(); len(q) != 1 || q[0] != kid {
		t.Fatalf("queued %v", q)
	}
	picky.set(func() { picky.forgetNo = false })
	// Run does this at its start and every minute.
	g.s.forgetPending(context.Background())
	if g.opens(kid) {
		t.Fatal("the queued key was not forgotten")
	}
	if q, _ := g.s.st.toForget(); len(q) != 0 {
		t.Fatalf("still queued %v", q)
	}
	// A denied consent's key goes the same way.
	d := g.start(cimdID, cimdBack, "")
	dkid := g.kidOf(d)
	resp, _ := http.Post(g.srv.URL+"/oauth/requests/"+d.rid+"/deny", "", nil)
	resp.Body.Close()
	if q, _ := g.s.st.toForget(); len(q) != 0 {
		t.Fatalf("a denied key left queued: %v", q)
	}
	if err := g.keys.Keep(context.Background(), dkid); !errors.Is(err, keys.ErrUnknownKey) {
		t.Fatalf("a denied key is still pending: %v", err)
	}
}

// The code is eight characters, drawn evenly, and an owner may type it
// with a dash or in lower case.
func TestTheCodeIsLongAndEven(t *testing.T) {
	counts := map[byte]int{}
	const n = 20_000
	for range n {
		c := shortCode()
		if len(c) != codeLen || strings.Trim(c, codeAlphabet) != "" {
			t.Fatalf("code %q", c)
		}
		for i := range len(c) {
			counts[c[i]]++
		}
	}
	want := float64(n*codeLen) / float64(len(codeAlphabet))
	for i := range len(codeAlphabet) {
		if got := float64(counts[codeAlphabet[i]]); got < 0.9*want || got > 1.1*want {
			t.Errorf("%c drawn %v times, want about %v", codeAlphabet[i], got, want)
		}
	}
	if normalizeCode(strings.ToLower(showCode("ABCD2345"))) != "ABCD2345" || normalizeCode("ABC-234") != "" {
		t.Fatal("normalizeCode")
	}
}

// Only the browser that started a request keeps a stream, at most two at
// once; anyone else gets the state once.
func TestEventStreamsAreBounded(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	_, stop1 := g.events(f, true)
	defer stop1()
	_, stop2 := g.events(f, true)
	defer stop2()
	time.Sleep(20 * time.Millisecond)
	req, _ := http.NewRequest(http.MethodGet, g.srv.URL+"/oauth/requests/"+f.rid+"/events", nil)
	req.AddCookie(f.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("a third stream: %d", resp.StatusCode)
	}
}

// A redirect_uri the authorize request named must be named again at the
// token endpoint, the same.
func TestTheTokenRequestNamesTheRedirect(t *testing.T) {
	g := newRig(t)
	for _, redirect := range []string{"", "https://example.com/elsewhere"} {
		f := g.start(cimdID, cimdBack, "")
		ch, stop := g.events(f, true)
		next(t, ch)
		g.roster(home, agentDevice(f.agentKey(t), ScopeLiveRead))
		code := redirectOf(t, next(t, ch)).Query().Get("code")
		stop()
		form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {f.verifier}}
		if redirect != "" {
			form.Set("redirect_uri", redirect)
		}
		if status, _ := g.token(form); status != http.StatusBadRequest {
			t.Fatalf("redirect_uri %q: %d", redirect, status)
		}
	}
}

// A code used again after its consent was swept still revokes what its
// first use got.
func TestACodeReusedAfterTheSweepStillRevokes(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentFor(f.agentKey(t), cimdID, g.now().Add(30*24*time.Hour), ScopeLiveRead))
	code := redirectOf(t, next(t, ch)).Query().Get("code")
	form := url.Values{"grant_type": {grantCode}, "code": {code}, "client_id": {cimdID}, "code_verifier": {f.verifier},
		"redirect_uri": {cimdBack}}
	status, tk := g.token(form)
	if status != http.StatusOK {
		t.Fatalf("first use: %d", status)
	}
	g.advance(RequestTTL + time.Minute)
	g.s.sweep(context.Background())
	if _, ok, _ := g.s.st.consentByRID(f.rid); ok {
		t.Fatal("the consent outlived the sweep")
	}
	if status, _ := g.token(form); status != http.StatusBadRequest {
		t.Fatalf("second use: %d", status)
	}
	if status, _ := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}}); status != http.StatusBadRequest {
		t.Fatalf("the first use's refresh token after the code came back: %d", status)
	}
}

// A refresh retried within a few seconds works once more, since its answer
// may have been lost; a third use revokes the family.
func TestARefreshRetryWithinTheGrace(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, "")
	tk := g.approve(f, cimdID)
	form := url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}}
	status, tk2 := g.token(form)
	if status != http.StatusOK {
		t.Fatalf("refresh: %d", status)
	}
	g.advance(refreshGrace / 2)
	status, tk3 := g.token(form)
	if status != http.StatusOK || tk3.Refresh == tk2.Refresh {
		t.Fatalf("a retry within the grace: %d", status)
	}
	if status, _ := g.token(form); status != http.StatusBadRequest {
		t.Fatalf("a third use: %d", status)
	}
	for _, a := range []string{tk2.Access, tk3.Access} {
		if _, aerr := g.bearer(a); aerr == nil {
			t.Fatal("a third use left the family alive")
		}
	}
}

// The support tooling's client id is not a metadata client: support's
// offers never come through this page.
func TestSupportsClientIDIsRefused(t *testing.T) {
	g := newRig(t)
	q, _ := g.authorizeParams(protocol.SupportClientID, "https://cloud.ftw.energy/cb", "")
	resp, _ := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" {
		t.Fatalf("support's client id: %d", resp.StatusCode)
	}
}

// The pages a person sees ask the browser to use https only.
func TestPagesAskForHTTPS(t *testing.T) {
	g := newRig(t)
	q, _ := g.authorizeParams(cimdID, cimdBack, "")
	for _, target := range []string{"/oauth/authorize?" + q.Encode(), "/oauth/authorize?client_id=nobody"} {
		resp, _ := noFollow.Get(g.srv.URL + target)
		resp.Body.Close()
		if !strings.HasPrefix(resp.Header.Get("Strict-Transport-Security"), "max-age=") {
			t.Fatalf("%s: no HSTS", target)
		}
	}
}

// A registered client that never got an agent goes after a day; one with
// an agent stays.
func TestUnusedRegistrationsGo(t *testing.T) {
	g := newRig(t)
	register := func() string {
		resp, err := http.Post(g.srv.URL+"/oauth/register", "application/json",
			strings.NewReader(`{"client_name":"X","redirect_uris":["https://x.example/cb"]}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out["client_id"].(string)
	}
	idle, used := register(), register()
	f := g.start(used, "https://x.example/cb", "")
	ch, stop := g.events(f, true)
	defer stop()
	next(t, ch)
	g.roster(home, agentFor(f.agentKey(t), used, g.now().Add(30*24*time.Hour), ScopeLiveRead))
	next(t, ch)
	g.advance(clientIdle + time.Hour)
	g.s.sweep(context.Background())
	if _, ok, _ := g.s.st.client(idle); ok {
		t.Fatal("an unused registration stayed")
	}
	if _, ok, _ := g.s.st.client(used); !ok {
		t.Fatal("a registration with an agent went")
	}
}
