package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw-cloud/internal/mcp"
	"github.com/srcfl/ftw-cloud/internal/oauth"
)

// The routes for assistants read no home either, whatever they are asked:
// the authorization server knows agents and tokens, never readings, and
// /mcp answers nothing without a token.
func TestOAuthRoutesReadNoHome(t *testing.T) {
	s, home := newServer(t)
	sealer, _ := keys.FileSealerFromKey(bytes.Repeat([]byte{3}, 32))
	ks, err := keys.NewServer(t.TempDir(), sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := oauth.New(filepath.Join(t.TempDir(), "oauth.db"), ks.Local(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auth.Close() })
	s.OAuth = auth
	s.MCP = mcp.New(auth, mcp.NewPool(s.Store, s.Uplink, ks.Local(), func(string) ([]byte, bool) { return nil, false }, nil), nil)
	h := s.Handler()
	paths := append(append([]string{}, oauth.Routes...), "/oauth/requests/"+home, "/oauth/requests?code="+home[:6],
		"/oauth/authorize?client_id="+home, "/.well-known/oauth-protected-resource/"+home, "/mcp?home="+home)
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(m, p, nil)
			h.ServeHTTP(w, r)
			if bytes.Contains(w.Body.Bytes(), []byte("CANARY")) {
				t.Fatalf("%s %s returned a home's readings", m, p)
			}
			if w.Header().Get("Link") == "" {
				t.Fatalf("%s %s has no source link", m, p)
			}
		}
	}
	// The metadata is there.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte(oauth.Issuer)) {
		t.Fatalf("metadata: %d", w.Code)
	}
}
