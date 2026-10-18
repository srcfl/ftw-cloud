package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

func aliasProof(n byte) protocol.AgentInviteCode {
	return protocol.AgentInviteCode{V: 1, Home: "abcdefghijklmnopqrstuvwx23", Box: bytes.Repeat([]byte{0x31}, 32), Secret: bytes.Repeat([]byte{n}, 32)}
}

func TestShortInvitationAliasesAreUniqueIdempotentAndRechecked(t *testing.T) {
	g := newRig(t)
	live := true
	g.s.Invitation = func(home string, hash, box []byte) (time.Time, bool) { return g.now().Add(time.Hour), live }
	// First code AAA-AAA, then the same random candidate (collision), then
	// BBB-BBB. A collision never returns another invitation's code.
	g.s.aliases.random = bytes.NewReader(append(bytes.Repeat([]byte{0}, 12), bytes.Repeat([]byte{1}, 6)...))
	first, end, err := g.s.publishInvitation(aliasProof(1))
	if err != nil {
		t.Fatal(err)
	}
	if first != "AAA-AAA" || end.After(g.now().Add(inviteAliasFor)) {
		t.Fatalf("code or expiry: %s %v", first, end)
	}
	again, sameEnd, err := g.s.publishInvitation(aliasProof(1))
	if err != nil || again != first || !sameEnd.Equal(end) {
		t.Fatalf("lost publish reply created another code: %s %v", again, err)
	}
	second, _, err := g.s.publishInvitation(aliasProof(2))
	if err != nil || second != "BBB-BBB" {
		t.Fatalf("collision selected wrong invitation: %s %v", second, err)
	}
	p, err := g.s.resolveInvitation(" aaa - aaa ")
	if err != nil || !bytes.Equal(p.Secret, aliasProof(1).Secret) {
		t.Fatalf("normalization changed proof: %v", err)
	}
	live = false
	if _, err := g.s.resolveInvitation(first); err == nil {
		t.Fatal("cancelled or consumed hint still resolved")
	}
}

func TestPublishingAShortCodeNeedsTheStrongProofAndReturnsOnlyTheAlias(t *testing.T) {
	g := newRig(t)
	wanted := aliasProof(3)
	g.s.Invitation = func(home string, hash, box []byte) (time.Time, bool) {
		return g.now().Add(2 * time.Minute), home == wanted.Home && bytes.Equal(box, wanted.Box) && bytes.Equal(hash, protocol.AgentInviteHash(wanted.Home, wanted.Secret))
	}
	for _, p := range []protocol.AgentInviteCode{aliasProof(4), wanted} {
		proof, _ := p.Encode()
		body, _ := json.Marshal(map[string]string{"invitation": proof})
		r, _ := http.NewRequest(http.MethodPost, g.srv.URL+"/oauth/invitations", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://192.168.1.9:8080")
		resp, err := noFollow.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" || resp.Header.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("LAN publishing requires cookies or lacks CORS")
		}
		if !bytes.Equal(p.Secret, wanted.Secret) {
			if resp.StatusCode != http.StatusConflict {
				t.Fatal("wrong bearer proof published")
			}
			continue
		}
		var answer struct {
			Code        string
			ExpiresAtMs int64
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(data, &answer) != nil || normalizeInviteAlias(answer.Code) == "" || answer.ExpiresAtMs > g.now().Add(2*time.Minute).UnixMilli() {
			t.Fatalf("publication: %d %s", resp.StatusCode, data)
		}
		if strings.Contains(string(data), proof) || strings.Contains(string(data), wanted.Home) {
			t.Fatal("alias response leaked strong proof or home")
		}
	}
}

func TestExpiredOrRestartedAliasNeverResolves(t *testing.T) {
	g := newRig(t)
	g.s.Invitation = func(string, []byte, []byte) (time.Time, bool) { return g.now().Add(time.Hour), true }
	code, _, err := g.s.publishInvitation(aliasProof(5))
	if err != nil {
		t.Fatal(err)
	}
	g.s.aliases.mu.Lock()
	row := g.s.aliases.codes[normalizeInviteAlias(code)]
	row.until = g.now().Add(-time.Second)
	g.s.aliases.codes[normalizeInviteAlias(code)] = row
	g.s.aliases.mu.Unlock()
	if _, err := g.s.resolveInvitation(code); err == nil {
		t.Fatal("expired alias resolved")
	}
	g.s.aliases = inviteAliases{}
	if _, err := g.s.resolveInvitation(code); err == nil {
		t.Fatal("a process restart invented an alias")
	}
}

func TestRestartCannotGiveAnUnexpiredCodeToAnotherHome(t *testing.T) {
	g := newRig(t)
	g.s.Invitation = func(string, []byte, []byte) (time.Time, bool) { return g.now().Add(time.Hour), true }
	g.s.aliases.random = bytes.NewReader(bytes.Repeat([]byte{0}, 6))
	old, _, err := g.s.publishInvitation(aliasProof(6))
	if err != nil {
		t.Fatal(err)
	}
	g.s.aliases = inviteAliases{random: bytes.NewReader(append(bytes.Repeat([]byte{0}, 6), bytes.Repeat([]byte{1}, 6)...))}
	other := aliasProof(7)
	other.Home = "bbcdefghijklmnopqrstuvwx23"
	fresh, _, err := g.s.publishInvitation(other)
	if err != nil || fresh == old {
		t.Fatalf("old code was reissued: %s %v", fresh, err)
	}
	if _, err := g.s.resolveInvitation(old); err == nil {
		t.Fatal("old code reached a different home")
	}
}

func TestNormalOAuthUpkeepDropsExpiredInvitationSecretsWithoutNewPublications(t *testing.T) {
	g := newRig(t)
	g.s.Invitation = func(string, []byte, []byte) (time.Time, bool) { return g.now().Add(time.Hour), true }
	if _, _, err := g.s.publishInvitation(aliasProof(8)); err != nil {
		t.Fatal(err)
	}
	g.advance(inviteAliasFor + time.Second)
	g.s.sweep(context.Background())
	if len(g.s.aliases.codes) != 0 || len(g.s.aliases.fingerprints) != 0 {
		t.Fatal("upkeep retained an expired bearer mapping")
	}
}
