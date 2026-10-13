package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/uplink"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	st := store.New(nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{Store: st, Registry: reg, Uplink: uplink.New(st, reg, key, log), Log: log}

	// A home with readings in it, held the way a box's uplink holds them.
	box, _ := st.For(store.Principal{Kind: store.Box, Home: "canaryhome"})
	box.Connected()
	_ = box.Put(cloudwire.MsgLive, []byte("CANARY-READING"), 1, true)
	return s, "canaryhome"
}

// No route reads a home. Every path answers without the canary, whatever the
// method or the query asks for.
func TestNoRouteReadsAHome(t *testing.T) {
	if devRoutes != nil {
		t.Skip("built with -tags ftwclouddev, which adds a local inspection route on purpose")
	}
	s, home := newServer(t)
	h := s.Handler()
	paths := append(slices.Clone(Routes), "/", "/v1", "/v1/home", "/admin", "/debug/pprof/", "/metrics",
		"/dev/held", "/dev/held?home="+home, "/v1/now?home="+home, "/v1/app?home="+home)
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(m, p, nil)
			r.RemoteAddr = "127.0.0.1:1"
			h.ServeHTTP(w, r)
			if bytes.Contains(w.Body.Bytes(), []byte("CANARY")) {
				t.Fatalf("%s %s returned a home's readings", m, p)
			}
			if w.Header().Get("Link") == "" {
				t.Fatalf("%s %s has no source link", m, p)
			}
		}
	}
}

func TestSourceSaysWhereTheSourceIs(t *testing.T) {
	s, _ := newServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/source", nil))
	if w.Code != http.StatusServiceUnavailable || !bytes.Contains(w.Body.Bytes(), []byte("github.com/srcfl/ftw-cloud")) {
		t.Fatalf("development /source: %d %s", w.Code, w.Body.String())
	}
}

func TestTheUplinkRefusesPlainHTTP(t *testing.T) {
	s, _ := newServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/box", nil))
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP to /v1/box: %d", w.Code)
	}
}
