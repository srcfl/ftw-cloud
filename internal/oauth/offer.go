package oauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
)

// The grant offer (docs/agents.md in srcfl/ftw, "The grant offer"): what the
// consent page asks the owner to grant, signed by the keys part's offer key,
// which the app pins. The QR and the universal link carry it in the link's
// fragment; the short code finds it once, for the box's page or an owner
// who types it.

var detEnc = func() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// Proposed caps for an offer with control. The owner may grant less; the
// box holds any grant to its own limits.
var proposedHoldCaps = protocol.Caps{HoldS: protocol.HoldSMax, MaxW: 11_000, PerMin: protocol.PerMinDefault}

// buildOffer is the offer for one consent: the agent's key, what its client
// asks for, and the code on the page. The home is left empty: the owner
// picks it, in the app or on the box's page.
func buildOffer(c consent) protocol.GrantOffer {
	scopes := slices.Sorted(slices.Values(splitScope(c.Scope)))
	var ops []string
	for op, scope := range protocol.RegistryAgentOps {
		if slices.Contains(scopes, scope) {
			ops = append(ops, op)
		}
	}
	slices.Sort(ops)
	var caps protocol.Caps
	if slices.Contains(scopes, ScopeDispatchHold) {
		caps = proposedHoldCaps
	} else if len(ops) > 0 {
		caps.PerMin = protocol.PerMinDefault
	}
	return protocol.GrantOffer{V: protocol.GrantOfferVersion, Key: c.AgentKey, Role: protocol.RoleAgent,
		Client: c.ClientName, ClientID: c.ClientID, ClientHost: c.ClientHost, Verified: c.Verified,
		Scopes: scopes, Ops: ops, Caps: caps, TTLS: uint64(protocol.AgentMaxMs / 1000), Code: c.Code,
		ExpMs: min(c.Expires.UnixMilli(), c.Created.UnixMilli()+protocol.OfferTTLMs)}
}

// signOffer encodes and signs an offer as the contract's SignedOffer
// {o, kid, sig}, base64url, for the link's fragment and the code lookup.
func (s *Server) signOffer(ctx context.Context, o protocol.GrantOffer) (string, error) {
	pub, err := s.offerPub(ctx)
	if err != nil {
		return "", err
	}
	raw, err := detEnc.Marshal(o)
	if err != nil {
		return "", err
	}
	sig, err := s.keys.SignOffer(ctx, raw)
	if err != nil {
		return "", err
	}
	out, err := detEnc.Marshal(protocol.SignedOffer{O: raw, Kid: keys.OfferKid(pub), Sig: sig})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// offerPub is the offer key's public half, asked of the keys part once.
func (s *Server) offerPub(ctx context.Context) ([]byte, error) {
	s.offerKey.mu.Lock()
	pub := s.offerKey.pub
	s.offerKey.mu.Unlock()
	if pub != nil {
		return pub, nil
	}
	pub, err := s.keys.OfferKey(ctx)
	if err != nil {
		return nil, err
	}
	s.offerKey.mu.Lock()
	s.offerKey.pub = pub
	s.offerKey.mu.Unlock()
	return pub, nil
}

// appLink is the universal link the QR and the button carry: the request
// id in the path, for the app's answer, and the signed offer in the
// fragment, which no server sees.
func appLink(rid, offer string) string { return AppLink + rid + "#" + offer }

// verifiedHosts are clients FTW Cloud knows by the host of their metadata
// document. A client from one of them is shown as verified; any other is
// shown by its host and the name it gives itself.
var verifiedHosts = []string{"claude.ai", "claude.com", "anthropic.com", "chatgpt.com", "openai.com", "grok.com", "x.ai"}

func verifiedHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range verifiedHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// offerKey serves the offer key's public half, so anyone can check what the
// app pins.
type offerKey struct {
	mu  sync.Mutex
	pub []byte
}

func (s *Server) serveOfferKey(w http.ResponseWriter, r *http.Request) {
	pub, err := s.offerPub(r.Context())
	if err != nil {
		http.Error(w, "the offer key is not available", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	writeJSON(w, http.StatusOK, map[string]any{"alg": "ES256", "tag": protocol.OfferTag, "kid": keys.OfferKid(pub),
		"pub": base64.RawURLEncoding.EncodeToString(pub)}, true)
}
