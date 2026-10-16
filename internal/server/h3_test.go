package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/srcfl/ftw-cloud/internal/quicdoor"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// h3 serves the stack's routes over HTTP/3 on a loopback UDP port with the
// stack's certificate, and returns an HTTP/3 client for them and the base
// URL.
func (s *stack) h3() (*http.Client, string) {
	s.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		s.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = quicdoor.New(s.srv.Config.Handler, nil).Serve(ctx, pc, &tls.Config{Certificates: s.srv.TLS.Certificates})
	}()
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	s.t.Cleanup(func() {
		_ = tr.Close()
		cancel()
		<-done
	})
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}, "https://" + pc.LocalAddr().String()
}

// The watch's one-shot read and its token read work over HTTP/3 as over
// TCP: the same handler, the same Noise, the box's bytes unchanged.
func TestAWatchReadsItsHomeOverHTTP3(t *testing.T) {
	s := newStack(t)
	box := s.connectBox()
	watchKey, _ := appwire.GenerateKeyPair()
	box.roster(1, cloudwire.Device{ID: "watch", Key: watchKey.Public(), Role: "watch",
		Scopes: []string{protocol.ScopeLiveRead, protocol.ScopePlanRead, protocol.ScopeEventsRead}, Epoch: 1})
	box.live(true)
	box.hb()
	waitHeld(t, s.st, box.home, watchKey, 2)

	c, base := s.h3()
	watch := &watchClient{t: t, http: c, base: base, key: watchKey, service: s.noise.Public(), home: box.home}
	view := cloudwire.NewView(box.home, &box.key.PublicKey)
	status, snap, all := watch.read(view, cloudwire.Have{}, cloudwire.HzLooking)
	if status != http.StatusOK || !snap.Online || len(all) != 2 {
		t.Fatalf("read over HTTP/3: %d, online %v, %d envelopes", status, snap.Online, len(all))
	}
	if g := view.Grade(time.Now().UnixMilli()); !g.Anchored || g.Sources["m"] != protocol.SourceLive {
		t.Fatalf("the read over HTTP/3 grades %+v", g)
	}

	status, reply, _ := watch.call(cloudwire.MsgTokenGet, struct{}{})
	env, _ := cloudwire.DecodeEnvelope(reply)
	var tok cloudwire.Token
	if status != http.StatusOK || env.T != cloudwire.MsgToken || cloudwire.Unmarshal(env.B, &tok) != nil {
		t.Fatalf("token.get over HTTP/3: %d %q", status, env.T)
	}
	req, _ := http.NewRequest(http.MethodGet, base+"/v1/now", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 3 {
		t.Fatalf("/v1/now over HTTP/3: %d %s", resp.StatusCode, resp.Proto)
	}

	// The sockets are not served over HTTP/3.
	for _, p := range []string{"/v1/box", "/v1/app?home=" + box.home} {
		resp, err := c.Get(base + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 400 {
			t.Fatalf("%s over HTTP/3: %d", p, resp.StatusCode)
		}
	}
}

// TCP responses point at HTTP/3, except a WebSocket upgrade's: a client
// that learned HTTP/3 there might try its socket over HTTP/3 next.
func TestAltSvcIsOnPlainResponsesOnly(t *testing.T) {
	s, home := newServer(t)
	s.AltSvc = quicdoor.AltSvc(443)
	h := s.Handler()
	for _, p := range []string{"/healthz", "/source", "/v1/now", "/v1/app/once?home=" + home} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Header().Get("Alt-Svc") != s.AltSvc {
			t.Fatalf("%s: Alt-Svc %q", p, w.Header().Get("Alt-Svc"))
		}
	}
	for _, p := range []string{"/v1/box", "/v1/app?home=" + home} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, p, nil)
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
		h.ServeHTTP(w, r)
		if w.Header().Get("Alt-Svc") != "" {
			t.Fatalf("an upgrade to %s carried Alt-Svc", p)
		}
	}
	s.AltSvc = ""
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Header().Get("Alt-Svc") != "" {
		t.Fatal("Alt-Svc without HTTP/3")
	}
}
