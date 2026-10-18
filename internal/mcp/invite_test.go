package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Core's own tunnel suite tests consumption at the first Noise proof. This
// TLS test covers the recipient page, pending key, tunnel, signed roster,
// Keep, PKCE and the resulting ordinary MCP read together.
func TestAnInvitationConnectsTheRecipientsOwnMCPKey(t *testing.T) {
	w := newWorld(t)
	b := w.connectBox()
	secret := bytes.Repeat([]byte{0x98}, 32)
	keyClient := w.keys.Local()
	defer keyClient.Close()
	pub, err := keyClient.OfferKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	claimed := make(chan struct{}, 1)
	b.mu.Lock()
	b.inviteHints = []cloudwire.Pending{{Kind: protocol.RoleAgent, Hash: protocol.AgentInviteHash(b.home, secret), TTLS: 7200}}
	b.inviteAdmission = func(key, payload []byte) (func(), bool) {
		claim, err := protocol.ParseAgentInviteClaim(payload)
		if err != nil || !bytes.Equal(claim.Secret, secret) {
			return nil, false
		}
		offer, err := protocol.OpenOffer(map[string][]byte{keys.OfferKid(pub): pub}, claim.Offer, time.Now().UnixMilli())
		if err != nil || !bytes.Equal(offer.Key, key) {
			return nil, false
		}
		return func() {
			b.mu.Lock()
			b.inviteHints = nil
			b.inviteAdmission = nil
			b.mu.Unlock()
			b.approve(key, offer.ClientID, protocol.ScopeLiveRead)
			claimed <- struct{}{}
		}, true
	}
	b.mu.Unlock()
	b.sendRoster()
	code, err := (protocol.AgentInviteCode{V: 1, Home: b.home, Box: b.static.Public(), Secret: secret}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		_, ok := w.st.Invitation(b.home, protocol.AgentInviteHash(b.home, secret), b.static.Public())
		return ok
	})
	publishBody, _ := json.Marshal(map[string]string{"invitation": code})
	response, err := w.client().Post(w.srv.URL+"/oauth/invitations", "application/json", bytes.NewReader(publishBody))
	if err != nil {
		t.Fatal(err)
	}
	var alias struct{ Code string }
	if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&alias) != nil || len(alias.Code) != 7 {
		t.Fatal("strong invitation did not get a short code")
	}
	response.Body.Close()
	code = alias.Code
	w.claimInvitation = func(rid string, cookie *http.Cookie) {
		body, _ := json.Marshal(map[string]string{"code": code})
		r, _ := http.NewRequest(http.MethodPost, w.srv.URL+"/oauth/requests/"+rid+"/invite", bytes.NewReader(body))
		r.Header.Set("Origin", "https://cloud.ftw.energy")
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(cookie)
		resp, err := w.client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
			t.Fatalf("invitation: %d %s", resp.StatusCode, data)
		}
	}
	a := w.connect(b, protocol.ScopeLiveRead+" "+protocol.ScopeSetupWrite)
	select {
	case <-claimed:
	default:
		t.Fatal("no proved claim")
	}
	if a.scope != protocol.ScopeLiveRead {
		t.Fatalf("invitation widened rights: %s", a.scope)
	}
	_, failed, message := a.call("status", nil)
	if failed {
		t.Fatalf("claimed key did not read its own home: %s", message)
	}
	b.remove(a.agentKey)
	waitFor(t, func() bool {
		return a.rpc("tools/call", map[string]any{"name": "status"}, true).Status == http.StatusUnauthorized
	})
}
