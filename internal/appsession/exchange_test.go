package appsession

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// exchanger is the uplink as a one-shot request sees it: what reached the
// box, and the box's answer. hold, when set, keeps each exchange open until
// it closes.
type exchanger struct {
	mu     sync.Mutex
	got    []cloudwire.X
	answer []byte
	hold   chan struct{}
}

func (e *exchanger) Exchange(_ context.Context, _ string, dev string, d []byte) []byte {
	e.mu.Lock()
	e.got = append(e.got, cloudwire.X{Dev: dev, D: d})
	hold := e.hold
	e.mu.Unlock()
	if hold != nil {
		<-hold
	}
	return e.answer
}

func (e *exchanger) sent() []cloudwire.X {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.got
}

// xOf reads an exchange's message 2.
func xOf(t *testing.T, payload []byte) []byte {
	t.Helper()
	env, err := cloudwire.DecodeEnvelope(payload)
	var x cloudwire.AppX
	if err != nil || env.T != cloudwire.MsgX || len(env.Sig) != 0 || cloudwire.Unmarshal(env.B, &x) != nil {
		t.Fatalf("message 2 is %+v: %v", env, err)
	}
	return x.D
}

// A watch's exchange is admitted by its roster entry's tun, so commands work
// with the readable copy off; everything else it may do needs the copy. The
// device that reaches the box is the one the handshake proved, whatever the
// body says.
func TestOnceAdmitsAnExchangeByTun(t *testing.T) {
	watch, _ := appwire.GenerateKeyPair()
	stranger, _ := appwire.GenerateKeyPair()
	for _, c := range []struct {
		name              string
		key               appwire.KeyPair
		tun, copyOn, susp bool
		wantX, wantRead   int
	}{
		{"tun, the copy off", watch, true, false, false, http.StatusOK, http.StatusForbidden},
		{"tun, the copy on", watch, true, true, false, http.StatusOK, http.StatusOK},
		{"no tun, the copy on", watch, false, true, false, http.StatusForbidden, http.StatusOK},
		{"no tun, the copy off", watch, false, false, false, http.StatusForbidden, http.StatusForbidden},
		{"suspended", watch, true, true, true, http.StatusForbidden, http.StatusForbidden},
		{"a key the roster lacks", stranger, true, true, false, http.StatusForbidden, http.StatusForbidden},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			e := &exchanger{answer: []byte("the box's answer")}
			h.app.Exchange = e
			grant := cloudwire.Grant{ID: make([]byte, 16), Controller: cloudwire.ControllerSourceful}
			if c.copyOn {
				grant.Scopes, grant.Purposes = []string{protocol.ScopeLiveRead}, []string{protocol.CloudPurposeServe}
			}
			h.rosterN++
			h.box.SetRoster(&cloudwire.Roster{RosterSeq: h.rosterN, TTLS: 86_400, Grant: grant,
				Devices: append(h.devices(1, 1), cloudwire.Device{ID: "watch", Key: watch.Public(), Role: "watch",
					Tun: c.tun, Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1})})
			if c.susp {
				_ = h.reg.Suspend(h.home, "watch", 1, time.Now())
			}
			h.live(true)
			// A dev and an id in the body are not the watch's to give.
			a := h.once(onceOpts{key: c.key, t: cloudwire.MsgX,
				body: map[string]any{"d": []byte("message 1"), "dev": "owner", "id": 7}})
			if a.status != c.wantX {
				t.Fatalf("x: %d, want %d", a.status, c.wantX)
			}
			if sent := e.sent(); a.status == http.StatusOK {
				if len(sent) != 1 || sent[0].Dev != "watch" || string(sent[0].D) != "message 1" {
					t.Fatalf("the box got %+v", sent)
				}
				if d := xOf(t, a.payload); string(d) != "the box's answer" {
					t.Fatalf("the watch got %q", d)
				}
			} else if len(sent) != 0 {
				t.Fatalf("a refused exchange reached the box: %+v", sent)
			}
			if a := h.once(onceOpts{key: c.key}); a.status != c.wantRead {
				t.Fatalf("read: %d, want %d", a.status, c.wantRead)
			}
		})
	}
}

// d longer than XDataMax is refused before it reaches the box; no box, or
// none that answers, is an empty d and not an error.
func TestAnExchangesSizeAndNoAnswer(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.setRoster(append(h.devices(1, 1), cloudwire.Device{ID: "watch", Key: watch.Public(), Role: "watch", Tun: true,
		Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1}), protocol.ScopeLiveRead)
	if a := h.once(onceOpts{key: watch, t: cloudwire.MsgX, body: cloudwire.AppX{D: make([]byte, cloudwire.XDataMax)}}); a.status != http.StatusOK || len(xOf(t, a.payload)) != 0 {
		t.Fatalf("without an exchanger: %d", a.status)
	}
	e := &exchanger{}
	h.app.Exchange = e
	if a := h.once(onceOpts{key: watch, t: cloudwire.MsgX, body: cloudwire.AppX{D: make([]byte, cloudwire.XDataMax+1)}}); a.status != http.StatusBadRequest {
		t.Fatalf("a d over XDataMax: %d", a.status)
	}
	if a := h.once(onceOpts{key: watch, t: cloudwire.MsgX, body: cloudwire.AppX{D: []byte{1}}}); a.status != http.StatusOK || len(xOf(t, a.payload)) != 0 {
		t.Fatalf("no answer: %d", a.status)
	}
	if len(e.sent()) != 1 {
		t.Fatalf("the box got %d", len(e.sent()))
	}
}

// One request at a time per device holds an exchange for its whole wait.
func TestAnExchangeHoldsItsDevicesTurn(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.setRoster(append(h.devices(1, 1), cloudwire.Device{ID: "watch", Key: watch.Public(), Role: "watch", Tun: true,
		Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1}), protocol.ScopeLiveRead)
	e := &exchanger{answer: []byte{2}, hold: make(chan struct{})}
	h.app.Exchange = e
	done := make(chan onceAnswer, 1)
	go func() { done <- h.once(onceOpts{key: watch, t: cloudwire.MsgX, body: cloudwire.AppX{D: []byte{1}}}) }()
	waitFor(t, "the exchange to wait", func() bool { return len(e.sent()) == 1 })
	if a := h.once(onceOpts{key: watch, t: cloudwire.MsgX, body: cloudwire.AppX{D: []byte{1}}}); a.status != http.StatusTooManyRequests {
		t.Fatalf("a second exchange while one waits: %d", a.status)
	}
	if a := h.once(onceOpts{key: watch}); a.status != http.StatusTooManyRequests {
		t.Fatalf("a read while an exchange waits: %d", a.status)
	}
	if a := h.once(onceOpts{key: h.owner}); a.status != http.StatusOK {
		t.Fatalf("another device: %d", a.status)
	}
	close(e.hold)
	if a := <-done; a.status != http.StatusOK || string(xOf(t, a.payload)) != "\x02" {
		t.Fatalf("the exchange ended %d", a.status)
	}
}
