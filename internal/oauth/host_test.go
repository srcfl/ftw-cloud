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

// A host is shown and signed in ASCII: a name in punycode, an address as it
// is. One with no ASCII form is refused.
func TestHostsAreASCII(t *testing.T) {
	for in, want := range map[string]string{
		"claude.ai":      "claude.ai",
		"Claude.AI":      "claude.ai",
		"сlaude.ai":      "xn--laude-0ye.ai", // a Cyrillic с
		"bücher.example": "xn--bcher-kva.example",
		"127.0.0.1":      "127.0.0.1",
		"::1":            "::1",
	} {
		if got, ok := asciiHost(in); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "a_b.example", "xn--a.example", "exa‍mple.com", "ex ample.com", "-bad.example", "a..b", ".a.example"} {
		if got, ok := asciiHost(bad); ok {
			t.Errorf("%q has an ASCII form %q", bad, got)
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
	for _, bad := range []string{"https://exa‍mple.com/cb", "https://a_b.example/cb", "https://xn--a.example/cb"} {
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
