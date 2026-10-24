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

	"github.com/srcfl/ftw-cloud/internal/appsession"
	"github.com/srcfl/ftw-cloud/internal/energy"
	"github.com/srcfl/ftw-cloud/internal/fleet"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/statistics"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/token"
	"github.com/srcfl/ftw-cloud/internal/uplink"
	"github.com/srcfl/ftw/go/protocol/appwire"
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
	up := uplink.New(st, reg, key, log)
	noise, _ := appwire.GenerateKeyPair()
	s := &Server{Store: st, Registry: reg, Uplink: up, App: appsession.New(st, reg, up, noise, log),
		Tokens: token.New(st, reg, log), Log: log}

	s.Fleet, err = fleet.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	s.Statistics, err = statistics.New(reg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Energy, err = energy.New(reg, testGateway(t)); err != nil {
		t.Fatal(err)
	}
	up.Statistics = true
	s.Statistics.(*statistics.Service).Enabled = true
	// A home with readings in it, held the way a box's uplink holds them.
	const home = "canaryhomecanaryhomecanary"
	box, _ := st.For(store.Principal{Kind: store.Box, Home: home})
	box.Connected()
	_ = box.Put(cloudwire.MsgLive, []byte("CANARY-READING"), 1, true)
	return s, home
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
		"/dev/held", "/dev/held?home="+home, "/v1/now?home="+home, "/v1/app?home="+home, "/v1/app/once?home="+home)
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

// /source names the commit and the image digest, so anyone can check the
// running service against what CI built.
func TestSourceNamesRevisionAndImage(t *testing.T) {
	s, _ := newServer(t)
	const rev = "0123456789abcdef0123456789abcdef01234567"
	const img = "ghcr.io/srcfl/ftw-cloud@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	old := Revision
	Revision = rev
	t.Cleanup(func() { Revision = old })
	t.Setenv("FTW_CLOUD_IMAGE", img)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/source", nil))
	if got := w.Header().Get("X-Source-Revision"); got != rev {
		t.Fatalf("X-Source-Revision = %q", got)
	}
	if got := w.Header().Get("X-Source-Image"); got != img {
		t.Fatalf("X-Source-Image = %q", got)
	}
}

func TestTheSocketsRefusePlainHTTP(t *testing.T) {
	s, home := newServer(t)
	for _, p := range []string{"/v1/box", "/v1/app?home=" + home} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusUpgradeRequired {
			t.Fatalf("plain HTTP to %s: %d", p, w.Code)
		}
	}
}

// A host without a Noise key serves boxes and says /v1/app and the one-shot
// read are not there yet; phones read through the relay meanwhile, and a
// watch reads now on the box's exchange.
func TestWithoutANoiseKeyTheAppEndpointIsOff(t *testing.T) {
	s, home := newServer(t)
	s.App = nil
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/app?home="+home, nil),
		httptest.NewRequest(http.MethodPost, "/v1/app/once?home="+home, bytes.NewReader([]byte{1})),
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s without a Noise key: %d", r.URL.Path, w.Code)
		}
	}
}
