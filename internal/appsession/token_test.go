package appsession

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/token"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// tokens gives the harness a token service and /v1/now behind TLS, and
// returns a reader that answers with the status a token gets there.
func (h *harness) tokens(t *testing.T) func(tok string) int {
	t.Helper()
	svc := token.New(h.store, h.reg, nil)
	h.app.Tokens = svc
	srv := httptest.NewUnstartedServer(svc)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return func(tok string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/now", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
}

// getToken asks over the session and reads the answer, skipping any box
// envelope that arrives first.
func (p *phone) getToken() cloudwire.Token {
	p.t.Helper()
	p.send(cloudwire.MsgTokenGet, struct{}{})
	for {
		raw, code := p.next(2 * time.Second)
		if code != 0 {
			p.t.Fatalf("closed with %d", code)
		}
		env, err := cloudwire.DecodeEnvelope(raw)
		if err != nil {
			p.t.Fatal(err)
		}
		if env.T != cloudwire.MsgToken {
			continue
		}
		if len(env.Sig) != 0 {
			p.t.Fatal("the service signed its token answer")
		}
		var tok cloudwire.Token
		if err := cloudwire.Unmarshal(env.B, &tok); err != nil {
			p.t.Fatal(err)
		}
		return tok
	}
}

// A device asks for its token over its own session. It reads /v1/now, the
// next one replaces it, and the session goes on.
func TestADeviceGetsItsTokenOverItsSession(t *testing.T) {
	h := newHarness(t)
	read := h.tokens(t)
	h.live(true)
	viewer := h.mustDial(dialOpts{key: h.viewer})
	first := viewer.getToken()
	if first.ExpiresInS != int64(token.Life/time.Second) {
		t.Fatalf("expires in %d s", first.ExpiresInS)
	}
	if code := read(first.Token); code != http.StatusOK {
		t.Fatalf("the token read %d", code)
	}
	second := viewer.getToken()
	if code := read(first.Token); code != http.StatusUnauthorized {
		t.Fatalf("the replaced token read %d", code)
	}
	if code := read(second.Token); code != http.StatusOK {
		t.Fatalf("the new token read %d", code)
	}
	next := h.live(false)
	if got, code := viewer.next(time.Second); code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("the session did not go on: code %d", code)
	}
}

// An owner's suspension kills the device's token; lifting it does not bring
// the token back.
func TestASuspensionKillsTheToken(t *testing.T) {
	h := newHarness(t)
	read := h.tokens(t)
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	viewer := h.mustDial(dialOpts{key: h.viewer})
	tok := viewer.getToken()
	owner.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"})
	if code := viewer.closed(2 * time.Second); code != cloudwire.CloseDenied {
		t.Fatalf("the suspended viewer closed with %d", code)
	}
	if code := read(tok.Token); code != http.StatusUnauthorized {
		t.Fatalf("a suspended device's token read %d", code)
	}
	owner.send(cloudwire.MsgUnsuspend, cloudwire.Suspend{DeviceID: "viewer"})
	waitFor(t, "the suspension to lift", func() bool { return !h.reg.Suspended(h.home, "viewer", 1) })
	if code := read(tok.Token); code != http.StatusUnauthorized {
		t.Fatalf("lifting the suspension brought the token back: %d", code)
	}
}

// Without a token service, token.get is ignored and the session goes on.
func TestWithoutTokensTokenGetIsIgnored(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	owner.send(cloudwire.MsgTokenGet, struct{}{})
	next := h.live(false)
	if got, code := owner.next(time.Second); code != 0 || !bytes.Equal(got, next) {
		t.Fatalf("the session did not go on: code %d", code)
	}
}

// The suspended device's session ends even when its token cannot be dropped.
func TestASuspensionEndsTheSessionWhateverTheToken(t *testing.T) {
	h := newHarness(t)
	h.app.Tokens = failingTokens{}
	h.live(true)
	owner := h.mustDial(dialOpts{key: h.owner})
	viewer := h.mustDial(dialOpts{key: h.viewer})
	owner.send(cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"})
	if code := viewer.closed(2 * time.Second); code != cloudwire.CloseDenied {
		t.Fatalf("the suspended viewer closed with %d", code)
	}
}

type failingTokens struct{}

func (failingTokens) Issue(string, cloudwire.Device) (cloudwire.Token, error) {
	return cloudwire.Token{}, errors.New("no tokens")
}

func (failingTokens) Drop(string, string) error { return errors.New("the registry is down") }
