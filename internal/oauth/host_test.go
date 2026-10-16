package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
)

// A host is shown and signed in ASCII: a name in punycode when it has
// letters outside ASCII, an address in its canonical form. One a browser
// would read otherwise, or with no ASCII form, is refused.
func TestHostsAreASCII(t *testing.T) {
	for in, want := range map[string]string{
		"claude.ai":         "claude.ai",
		"Claude.AI":         "claude.ai",
		"сlaude.ai":         "xn--laude-0ye.ai", // a Cyrillic с
		"bücher.example":    "xn--bcher-kva.example",
		"xn--laude-0ye.ai":  "xn--laude-0ye.ai",
		"a_b.example":       "a_b.example",    // registered before, still works
		"ab--cd.example":    "ab--cd.example", // likewise
		"127.0.0.1":         "127.0.0.1",
		"::1":               "::1",
		"::0001":            "::1",
		"2001:DB8:0:0::1":   "2001:db8::1",
		"1.2.3.example":     "1.2.3.example",
		"example.0x10z":     "example.0x10z",
		"localhost":         "localhost",
		"router.local":      "router.local",
		"x.example.museum1": "x.example.museum1",
	} {
		if got, ok := asciiHost(in); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{
		"", "claude.ai.", "a..b", ".a.example", "-bad.example", "bad-.example", "ex ample.com", "exa\u200dmple.com",
		"2130706433", "0177.0.0.1", "0x7f.0.0.1", "0x7f.1", "127.1", "1.2.3.4.5", "example.123", "example.0x1f", "0x",
		"fe80::1%en0", "a\u202eb.example", strings.Repeat("a", 64) + ".example",
	} {
		if got, ok := asciiHost(bad); ok {
			t.Errorf("%q has an ASCII form %q", bad, got)
		}
	}
}

// A metadata document's URL names its host in lower case ASCII already.
func TestADocumentURLNamesItsHostInASCII(t *testing.T) {
	for _, u := range []string{"https://сlaude.ai/client.json", "https://Example.com/client.json", "https://claude.ai./client.json"} {
		if _, err := checkCIMDURL(u); err == nil {
			t.Errorf("%s was taken", u)
		}
	}
	if _, err := checkCIMDURL("https://xn--laude-0ye.ai/client.json"); err != nil {
		t.Fatalf("a punycode host was refused: %v", err)
	}
}

// Clients registered with an underscore or a "--" in a redirect host keep
// working: the authorize step checks the redirect again and takes them.
func TestRedirectsInASCIIStillWork(t *testing.T) {
	g := newRig(t)
	for _, redirect := range []string{"https://a_b.example/cb", "https://ab--cd.example/cb"} {
		resp, err := http.Post(g.srv.URL+"/oauth/register", "application/json",
			strings.NewReader(`{"client_name":"X","redirect_uris":["`+redirect+`"]}`))
		if err != nil {
			t.Fatal(err)
		}
		var reg map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&reg)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: %d %v", redirect, resp.StatusCode, reg)
		}
		f := g.start(reg["client_id"].(string), redirect, "")
		if want := strings.TrimSuffix(strings.TrimPrefix(redirect, "https://"), "/cb"); f.view.Client.Host != want {
			t.Fatalf("%s shows %q", redirect, f.view.Client.Host)
		}
	}
}

// A registered client whose redirect looks like claude.ai in another script
// reaches the owner, the box page and the signed offer as the punycode name
// it is; a redirect with no ASCII form does not register.
func TestALookAlikeHostIsShownAndSignedAsPunycode(t *testing.T) {
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
	for _, bad := range []string{"https://exa\u200dmple.com/cb", "https://claude.ai./cb", "https://2130706433/cb", "https://0177.0.0.1/cb"} {
		if status, out := register(`{"client_name":"X","redirect_uris":["` + bad + `"]}`); status != http.StatusBadRequest {
			t.Fatalf("%q registered: %d %v", bad, status, out)
		}
	}

	lookAlike := "https://сlaude.ai/cb"
	status, reg := register(`{"client_name":"Claude","client_uri":"https://сlaude.ai","redirect_uris":["` + lookAlike + `"]}`)
	if status != http.StatusCreated {
		t.Fatalf("register: %d %v", status, reg)
	}
	f := g.start(reg["client_id"].(string), lookAlike, "")
	if f.view.Client.Host != "xn--laude-0ye.ai" {
		t.Fatalf("the box page shows %q", f.view.Client.Host)
	}

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
		t.Fatal(err)
	}
	if o.ClientHost != "xn--laude-0ye.ai" {
		t.Fatalf("the offer signs %q", o.ClientHost)
	}

	q, _ := g.authorizeParams(reg["client_id"].(string), lookAlike, "")
	resp, err := noFollow.Get(g.srv.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(page, []byte("сlaude")) || !bytes.Contains(page, []byte("xn--laude-0ye.ai")) {
		t.Fatal("the consent page shows the look-alike, not its punycode")
	}
}
