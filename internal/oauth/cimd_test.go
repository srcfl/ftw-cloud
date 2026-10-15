package oauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The client_id URL itself: only https to a DNS name on port 443, with a
// real path.
func TestCIMDURLRules(t *testing.T) {
	for _, bad := range []string{
		"http://example.com/client.json",
		"https://example.com",
		"https://example.com/",
		"https://127.0.0.1/client.json",
		"https://[::1]/client.json",
		"https://169.254.169.254/latest/meta-data",
		"https://example.com:8443/client.json",
		"https://user:pass@example.com/client.json",
		"https://example.com/client.json#frag",
		"https://example.com/a/../client.json",
		"https://example.com/./client.json",
		"https://localhost/client.json",
		"https://example.com./client.json",
		"https://" + strings.Repeat("a", cimdMaxURL) + ".com/x",
	} {
		if _, err := checkCIMDURL(bad); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	for _, good := range []string{"https://example.com/client.json", "https://claude.ai/oauth/mcp-client-metadata", "https://a.example:443/x"} {
		if _, err := checkCIMDURL(good); err != nil {
			t.Errorf("%s was refused: %v", good, err)
		}
	}
}

func TestPublicAddresses(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.40", "169.254.169.254", "100.64.0.1", "0.0.0.0",
		"224.0.0.1", "255.255.255.255", "198.18.0.1", "192.0.2.1", "::1", "::", "fe80::1", "fd00::1", "fc00::1",
		"::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1", "2002:a00:1::", "2001:db8::1", "ff02::1",
	} {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s counts as public", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "13.50.84.149", "2606:4700:4700::1111", "::ffff:1.1.1.1"} {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s does not count as public", s)
		}
	}
}

// fenced is the production fence with a resolver the test chooses: every
// name below is refused before a socket opens, and dial counts any socket
// that would have.
func fenced(t *testing.T, answers map[string][]string) (*fetcher, *atomic.Int32) {
	f := newFetcher(nil)
	var dialled atomic.Int32
	f.resolve = func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range answers[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if out == nil {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
	f.dial = func(context.Context, string, string) (net.Conn, error) {
		dialled.Add(1)
		return nil, errors.New("test: no network")
	}
	return f, &dialled
}

// A name that resolves anywhere inside is refused before connecting:
// loopback, the private ranges, the cloud's metadata service, shared
// address space, IPv6 inside, IPv4 in IPv6, NAT64, and a name that mixes a
// public answer with a private one.
func TestCIMDRefusesInsideAddresses(t *testing.T) {
	answers := map[string][]string{
		"loop.example":      {"127.0.0.1"},
		"ten.example":       {"10.0.0.7"},
		"meta.example":      {"169.254.169.254"},
		"cgnat.example":     {"100.64.1.1"},
		"v6loop.example":    {"::1"},
		"ula.example":       {"fd12:3456::1"},
		"mapped.example":    {"::ffff:192.168.1.40"},
		"nat64.example":     {"64:ff9b::a9fe:a9fe"},
		"mixed.example":     {"1.1.1.1", "10.0.0.1"},
		"zero.example":      {"0.0.0.0"},
		"linklocal.example": {"fe80::1"},
	}
	f, dialled := fenced(t, answers)
	for host := range answers {
		_, err := f.get(context.Background(), "https://"+host+"/client.json")
		if !errors.Is(err, errCIMDAddress) {
			t.Errorf("%s: %v", host, err)
		}
	}
	if n := dialled.Load(); n != 0 {
		t.Fatalf("%d sockets opened toward inside addresses", n)
	}
	// The second check, as the socket connects, refuses too: a dialer
	// handed an inside address by any route does not connect.
	fresh := newFetcher(nil)
	if _, err := fresh.dial(context.Background(), "tcp", "127.0.0.1:443"); err == nil || !strings.Contains(err.Error(), errCIMDAddress.Error()) {
		t.Fatalf("connect-time check: %v", err)
	}
}

// What the document's server may do: redirect, send too much, be slow,
// answer an error, or serve a document that is not the client's. Each is a
// refusal, and a refusal is cached for a minute.
func TestCIMDServerMisbehaviour(t *testing.T) {
	g := newRig(t)
	var hits atomic.Int32
	slow := make(chan struct{})
	t.Cleanup(func() { close(slow) })
	g.cimd.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/redirect.json":
			http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
		case "/big.json":
			_, _ = w.Write([]byte(`{"client_name":"` + strings.Repeat("a", cimdMaxBytes) + `"}`))
		case "/slow.json":
			select {
			case <-slow:
			case <-r.Context().Done():
			}
		case "/error.json":
			http.Error(w, "nope", http.StatusInternalServerError)
		case "/mismatch.json":
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/other.json","client_name":"X","redirect_uris":["https://example.com/cb"]}`))
		case "/secret.json":
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/secret.json","client_name":"X","redirect_uris":["https://example.com/cb"],"client_secret":"s"}`))
		case "/custom.json":
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/custom.json","client_name":"X","redirect_uris":["myapp://cb"]}`))
		case "/jwt.json":
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/jwt.json","client_name":"X","redirect_uris":["https://example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`))
		case "/noname.json":
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/noname.json","redirect_uris":["https://example.com/cb"]}`))
		case "/html.json":
			_, _ = w.Write([]byte(`<html>`))
		case "/cached.json":
			w.Header().Set("Cache-Control", "max-age=600")
			_, _ = w.Write([]byte(`{"client_id":"https://example.com/cached.json","client_name":"Cached","redirect_uris":["https://example.com/cb"]}`))
		}
	})
	g.s.fetch.timeout = 300 * time.Millisecond
	for _, p := range []string{"redirect", "big", "slow", "error", "mismatch", "secret", "custom", "jwt", "noname", "html"} {
		start := time.Now()
		if _, err := g.s.fetch.get(context.Background(), "https://example.com/"+p+".json"); err == nil {
			t.Errorf("%s was accepted", p)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("%s took %s", p, time.Since(start))
		}
	}
	// Failures are cached: asking again does not fetch again.
	before := hits.Load()
	_, _ = g.s.fetch.get(context.Background(), "https://example.com/error.json")
	if hits.Load() != before {
		t.Fatal("a failed fetch was not cached")
	}
	// And so is a good document, for as long as it says, within bounds.
	for range 3 {
		md, err := g.s.fetch.get(context.Background(), "https://example.com/cached.json")
		if err != nil || md.ClientName != "Cached" {
			t.Fatalf("cached: %v", err)
		}
	}
	if hits.Load() != before+1 {
		t.Fatalf("a cacheable document was fetched %d times", hits.Load()-before)
	}
	g.advance(11 * time.Minute)
	_, _ = g.s.fetch.get(context.Background(), "https://example.com/cached.json")
	if hits.Load() != before+2 {
		t.Fatal("a document was kept past its max-age")
	}
}

func TestCacheFor(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"":                     cimdCacheNone,
		"no-store":             0,
		"max-age=0":            cimdCacheMin,
		"public, max-age=3600": time.Hour,
		"max-age=999999999":    cimdCacheMax,
		"max-age=x":            cimdCacheNone,
	} {
		if got := cacheFor(cc); got != want {
			t.Errorf("%q: %s, want %s", cc, got, want)
		}
	}
}

// The fence uses no proxy from the environment.
func TestCIMDIgnoresProxies(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	f := newFetcher(nil)
	if f.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("the fetcher reads a proxy")
	}
}
