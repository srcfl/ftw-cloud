package token

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// A home with a signed copy of every class, an owner and a viewer in its
// roster, and /v1/now behind TLS 1.3.
type harness struct {
	t      *testing.T
	clock  *clock
	store  *store.Store
	reg    *registry.Registry
	svc    *Service
	srv    *httptest.Server
	boxKey *ecdsa.PrivateKey
	home   string
	box    *store.Handle
	seq    uint64
	held   map[string][]byte
	rsq    uint64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	c := &clock{t: time.Now()}
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	st := store.New(c.now)
	st.UseSuspensions(reg.Suspended)
	svc := New(st, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	svc.now = c.now
	srv := httptest.NewUnstartedServer(svc)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	boxKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&boxKey.PublicKey)
	home := cloudwire.HomeID(pk)
	if err := reg.Claim(home, pk, c.t); err != nil {
		t.Fatal(err)
	}
	box, _ := st.For(store.Principal{Kind: store.Box, Home: home})
	box.Connected()
	h := &harness{t: t, clock: c, store: st, reg: reg, svc: svc, srv: srv, boxKey: boxKey, home: home, box: box,
		held: map[string][]byte{}}
	h.roster(1, protocol.CloudScopes...)
	return h
}

func (h *harness) devices(ownerEpoch uint64) []cloudwire.Device {
	return []cloudwire.Device{
		{ID: "owner", Key: bytes.Repeat([]byte{1}, 32), Role: "owner", Scopes: protocol.CloudScopes, Epoch: ownerEpoch},
		{ID: "viewer", Key: bytes.Repeat([]byte{2}, 32), Role: "viewer", Scopes: []string{protocol.ScopeLiveRead}},
	}
}

func (h *harness) roster(ownerEpoch uint64, grant ...string) *cloudwire.Roster {
	return h.setRoster(h.devices(ownerEpoch), grant...)
}

// setRoster holds a roster the way the uplink does, and lets the service drop
// the tokens it no longer allows.
func (h *harness) setRoster(devices []cloudwire.Device, grant ...string) *cloudwire.Roster {
	h.rsq++
	r := &cloudwire.Roster{RosterSeq: h.rsq, TTLS: 86_400, Devices: devices,
		Grant: cloudwire.Grant{ID: make([]byte, 16), Scopes: grant, Purposes: []string{protocol.CloudPurposeServe}, Controller: "sourceful"}}
	if !h.box.SetRoster(r) {
		h.t.Fatal("roster refused")
	}
	h.svc.Roster(h.home, r)
	return r
}

// put signs a body of class t as the box and holds it; name keys it for the
// test.
func (h *harness) put(name, t string, body any, table bool) {
	h.t.Helper()
	h.seq++
	hdr := cloudwire.Header{Seq: h.seq, Boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes), UptimeMs: int64(h.seq * 100)}
	env, err := cloudwire.Seal(h.boxKey, h.home, t, struct {
		cloudwire.Header
		Body any `cbor:"x"`
	}{hdr, body})
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := env.Encode()
	if err := h.box.Put(t, raw, h.seq, table); err != nil {
		h.t.Fatal(err)
	}
	h.held[name] = raw
}

// fill holds one envelope of every class, in this order.
func (h *harness) fill() {
	h.put("live full", cloudwire.MsgLive, "full", true)
	h.put("prices", cloudwire.MsgPrices, "p", false)
	h.put("lp", cloudwire.MsgLP, "lp", false)
	h.put("plan", cloudwire.MsgPlan, "plan", false)
	h.put("event", cloudwire.MsgEvent, "e", false)
	h.put("tiles", cloudwire.MsgTiles, "t", false)
	h.put("health", cloudwire.MsgHealth, "h", false)
	h.put("live delta", cloudwire.MsgLive, "delta", false)
	h.put("hb", cloudwire.MsgHB, "hb", false)
}

func (h *harness) issue(id string, epoch uint64) string {
	h.t.Helper()
	tok, err := h.svc.Issue(h.home, cloudwire.Device{ID: id, Epoch: epoch})
	if err != nil {
		h.t.Fatal(err)
	}
	if home, secret, ok := Split(tok.Token); tok.ExpiresInS != 7*24*3600 || !ok || home != h.home || len(secret) != 43 {
		h.t.Fatalf("token %q expires in %d s", tok.Token, tok.ExpiresInS)
	}
	return tok.Token
}

// get reads /v1/now with an Authorization header as given.
func (h *harness) get(auth string) (int, []byte) {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/now", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Cache-Control") != "no-store" {
		h.t.Fatal("a token read may be cached")
	}
	return resp.StatusCode, body
}

func (h *harness) now(token string) Now {
	h.t.Helper()
	code, body := h.get("Bearer " + token)
	if code != http.StatusOK {
		h.t.Fatalf("token read: %d", code)
	}
	var n Now
	if err := cloudwire.Unmarshal(body, &n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// The protocol's promise: a token reads live, prices and hb as the box
// signed them, in rising seq, and never lp, plan, event, tiles or health.
func TestATokenReadsLivePricesAndHBAndNothingElse(t *testing.T) {
	h := newHarness(t)
	h.fill()
	n := h.now(h.issue("owner", 1))
	want := []string{"live full", "prices", "live delta", "hb"}
	if len(n.Envelopes) != len(want) {
		t.Fatalf("a token read %d envelopes, want %v", len(n.Envelopes), want)
	}
	for i, name := range want {
		if !bytes.Equal(n.Envelopes[i], h.held[name]) {
			t.Fatalf("envelope %d is not the box's %s", i, name)
		}
		env, err := cloudwire.DecodeEnvelope(n.Envelopes[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := cloudwire.Verify(&h.boxKey.PublicKey, h.home, env); err != nil {
			t.Fatalf("%s does not verify with the box key: %v", name, err)
		}
	}
	if n.LastSeenMs != h.clock.t.UnixMilli() {
		t.Fatalf("lastSeenMs %d", n.LastSeenMs)
	}
}

// Every refusal is the same 401 with an empty body.
func TestRefusalsSayNothing(t *testing.T) {
	h := newHarness(t)
	h.fill()
	good := h.issue("owner", 1)
	stranger := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for name, auth := range map[string]string{
		"no header":       "",
		"another scheme":  "Basic " + good,
		"not base64url":   "Bearer !!!",
		"too short":       "Bearer " + good[:20],
		"a token unknown": "Bearer " + stranger,
	} {
		code, body := h.get(auth)
		if code != http.StatusUnauthorized || len(body) != 0 {
			t.Errorf("%s: %d %q", name, code, body)
		}
	}
	if code, _ := h.get("bearer " + good); code != http.StatusOK {
		t.Fatalf("the scheme is case-insensitive: %d", code)
	}
}

// A token stops reading when its roster entry goes, moves its epoch, is
// suspended, when the roster runs out, when the token expires, when a new
// token replaces it, and when the home is purged.
func TestATokenDiesWithItsAccess(t *testing.T) {
	refused := func(t *testing.T, h *harness, tok string) {
		t.Helper()
		if code, body := h.get("Bearer " + tok); code != http.StatusUnauthorized || len(body) != 0 {
			t.Fatalf("still reads: %d", code)
		}
	}
	t.Run("roster drops the device", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("viewer", 0)
		h.setRoster(h.devices(1)[:1], protocol.CloudScopes...)
		refused(t, h, tok)
		if _, ok, _ := h.reg.TokenLookup(hashOf(t, tok), h.clock.t); ok {
			t.Fatal("the roster left the token's row")
		}
	})
	t.Run("new epoch", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("owner", 1)
		h.roster(2, protocol.CloudScopes...)
		refused(t, h, tok)
	})
	t.Run("suspended", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("owner", 1)
		_ = h.reg.Suspend(h.home, "owner", 1, h.clock.t)
		refused(t, h, tok)
	})
	t.Run("roster runs out", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("owner", 1)
		h.clock.t = h.clock.t.Add(24*time.Hour + time.Second)
		refused(t, h, tok)
	})
	t.Run("expires", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("owner", 1)
		h.clock.t = h.clock.t.Add(Life - time.Second)
		h.roster(1, protocol.CloudScopes...)
		if code, _ := h.get("Bearer " + tok); code != http.StatusOK {
			t.Fatalf("a token a second from expiry: %d", code)
		}
		h.clock.t = h.clock.t.Add(time.Second)
		refused(t, h, tok)
	})
	t.Run("replaced", func(t *testing.T) {
		h := newHarness(t)
		old := h.issue("owner", 1)
		fresh := h.issue("owner", 1)
		refused(t, h, old)
		if code, _ := h.get("Bearer " + fresh); code != http.StatusOK {
			t.Fatalf("the new token: %d", code)
		}
	})
	t.Run("purged", func(t *testing.T) {
		h := newHarness(t)
		tok := h.issue("owner", 1)
		_ = h.reg.Purge(h.home, nil, h.clock.t)
		h.box.Delete()
		refused(t, h, tok)
	})
}

// Readings go an hour after the box does; the token then reads only when
// the box was last seen.
func TestATokenReadsNoReadingsAnHourAfterTheBox(t *testing.T) {
	h := newHarness(t)
	h.fill()
	tok := h.issue("owner", 1)
	gen := h.box.Connected()
	h.box.Disconnected(gen)
	h.clock.t = h.clock.t.Add(store.ReadingsKeptFor + time.Second)
	n := h.now(tok)
	if len(n.Envelopes) != 0 || n.LastSeenMs == 0 {
		t.Fatalf("after an hour: %d envelopes, last seen %d", len(n.Envelopes), n.LastSeenMs)
	}
}

func TestOnlyGETOverTLS13(t *testing.T) {
	h := newHarness(t)
	tok := h.issue("owner", 1)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/now", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", resp.StatusCode)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/now", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	h.svc.ServeHTTP(w, r)
	if w.Code != http.StatusUpgradeRequired || bytes.Contains(w.Body.Bytes(), []byte("envelopes")) {
		t.Fatalf("plain HTTP: %d", w.Code)
	}
}

func hashOf(t *testing.T, tok string) []byte {
	t.Helper()
	_, secret, _ := Split(tok)
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return sum[:]
}

// A token asked for by a device that a suspension or roster has just shut
// out is not kept: the access is checked again once the row is stored.
func TestATokenIsNotIssuedPastItsDevicesAccess(t *testing.T) {
	h := newHarness(t)
	_ = h.reg.Suspend(h.home, "owner", 1, h.clock.t)
	if _, err := h.svc.Issue(h.home, cloudwire.Device{ID: "owner", Epoch: 1}); err != store.ErrDenied {
		t.Fatalf("a suspended device got a token: %v", err)
	}
	if _, err := h.svc.Issue(h.home, cloudwire.Device{ID: "owner", Epoch: 2}); err != store.ErrDenied {
		t.Fatalf("a device at an epoch the roster does not list got a token: %v", err)
	}
	var n int
	if err := h.reg.TokenPrune(h.home, func(string, uint64) bool { n++; return true }); err != nil || n != 0 {
		t.Fatalf("refused tokens left %d rows", n)
	}
}

// A roster that moves a device's epoch drops the token of the old epoch and
// keeps one the device already got at the new epoch.
func TestAPruneKeepsATokenOfTheNewEpoch(t *testing.T) {
	h := newHarness(t)
	old := h.issue("owner", 1)
	r := h.roster(2, protocol.CloudScopes...)
	fresh := h.issue("owner", 2)
	h.svc.Roster(h.home, r)
	if code, _ := h.get("Bearer " + old); code != http.StatusUnauthorized {
		t.Fatalf("the old epoch's token read %d", code)
	}
	if code, _ := h.get("Bearer " + fresh); code != http.StatusOK {
		t.Fatalf("the new epoch's token read %d", code)
	}
}

// A token carries its home, so an instance that does not hold the home
// names the shard that does, and one whose home was changed is refused.
func TestATokenOfAnotherShardIsSentThere(t *testing.T) {
	h := newHarness(t)
	tok := h.issue("owner", 1)
	get := func(tok string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/v1/now", nil)
		r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13}
		r.Header.Set("Authorization", "Bearer "+tok)
		h.svc.ServeHTTP(w, r)
		return w
	}
	if w := get(tok); w.Code != http.StatusOK {
		t.Fatalf("on its own shard: %d", w.Code)
	}
	d, err := shard.File{Self: "s1", Default: "s1",
		Shards: map[string]string{"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
		Homes:  map[string]string{h.home: "s2"}}.Directory()
	if err != nil {
		t.Fatal(err)
	}
	h.svc.Shards = d
	w := get(tok)
	if w.Code != cloudwire.StatusWrongShard || w.Header().Get(cloudwire.ShardHeader) != "s2.cloud.ftw.energy" || w.Body.Len() != 0 {
		t.Fatalf("on another shard: %d %q %q", w.Code, w.Header().Get(cloudwire.ShardHeader), w.Body.String())
	}
	h.svc.Shards = nil
	_, secret, _ := Split(tok)
	if w := get("aaaaaaaaaaaaaaaaaaaaaaaaaa." + secret); w.Code != http.StatusUnauthorized {
		t.Fatalf("a token under another home: %d", w.Code)
	}
	// A token from before shards, the secret alone, still reads.
	if w := get(secret); w.Code != http.StatusOK {
		t.Fatalf("a token without its home: %d", w.Code)
	}
}
