package oauth

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestInvalidScopeDoesNotConsumeRefresh(t *testing.T) {
	g := newRig(t)
	f := g.start(cimdID, cimdBack, ScopeConfigRead)
	tk := g.approve(f, cimdID, ScopeConfigRead)
	status, refused := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}, "scope": {ScopeConfigRead + " " + ScopeSetupWrite}})
	if status != http.StatusBadRequest || refused.Error != "invalid_scope" {
		t.Fatal(status, refused.Error)
	}
	g.advance(refreshGrace + time.Second)
	status, retried := g.token(url.Values{"grant_type": {grantRefresh}, "refresh_token": {tk.Refresh}, "client_id": {cimdID}})
	if status != http.StatusOK {
		t.Errorf("a refused scope request consumed the original refresh token; valid retry returned %d %s", status, retried.Error)
	}
	if _, err := g.bearer(tk.Access); err != nil {
		t.Errorf("valid retry revoked the original read session: %v", err)
	}
}
