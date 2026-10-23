package appsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The one-shot read at /v1/app/once: a watch reads its home in one HTTPS
// request, because watchOS gives an app HTTPS and nothing lower (ADR 0009,
// decision 7). docs/protocol-cloud.md in srcfl/ftw, "One-shot read", is the
// wire format.
//
// The body is Noise IK message 1 to the service's Noise key, with
// cloudwire.OncePrologue(home) as the prologue. It carries one unsigned
// envelope: read, token.get, push.register, push.unregister or x, a watch's
// exchange message, which goes to the box and back unread ("Exchange"). The
// service admits the device as /v1/app admits a phone, through store.For
// with the key the handshake proved, and answers with message 2 and, for a
// read, the envelopes that did not fit, each after its length. It keeps no
// session and no Noise state after the answer; only the counts that bound
// how often a device, a home and the process may read.

const (
	// MaxOnceInFlight bounds the reads the process answers at once, counted
	// after their bodies are in. Each costs four X25519 operations.
	MaxOnceInFlight = 64
	// MaxOncePerHome bounds one home's reads at once, as its sessions are
	// bounded.
	MaxOncePerHome = store.MaxSessionsPerHome
)

// onceLimits counts the one-shot reads under way and when each device's
// recent reads began. It holds no session and no Noise state.
type onceLimits struct {
	mu      sync.Mutex
	process int
	homes   map[string]int
	devices map[string]*onceDevice
	swept   time.Time
}

// onceDevice is one device's reads: whether one is open, and when the reads
// of the last minute began.
type onceDevice struct {
	open bool
	at   []time.Time
}

func (l *onceLimits) enterProcess() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.process >= MaxOnceInFlight {
		return false
	}
	l.process++
	return true
}

func (l *onceLimits) leaveProcess() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.process--
}

// enter starts one admitted device's read, or reports a limit it would pass:
// one read at a time per device and cloudwire.OnceReadsPerMinute, and
// MaxOncePerHome at once per home.
func (l *onceLimits) enter(home string, key []byte, now time.Time) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > time.Minute {
		for k, d := range l.devices {
			if !d.open && (len(d.at) == 0 || now.Sub(d.at[len(d.at)-1]) > time.Minute) {
				delete(l.devices, k)
			}
		}
		l.swept = now
	}
	id := home + "\x00" + string(key)
	d := l.devices[id]
	if d == nil {
		d = &onceDevice{}
		l.devices[id] = d
	}
	d.at = slices.DeleteFunc(d.at, func(at time.Time) bool { return now.Sub(at) >= time.Minute })
	if d.open || len(d.at) >= cloudwire.OnceReadsPerMinute || l.homes[home] >= MaxOncePerHome {
		return nil, false
	}
	d.open = true
	d.at = append(d.at, now)
	l.homes[home]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		d.open = false
		if l.homes[home]--; l.homes[home] <= 0 {
			delete(l.homes, home)
		}
	}, true
}

// held counts what the limits hold: reads under way and devices known.
func (l *onceLimits) held() (open, devices int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, n := range l.homes {
		open += n
	}
	return open + l.process, len(l.devices)
}

// ServeOnce is /v1/app/once. Every refusal has an empty body.
func (s *Server) ServeOnce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		http.Error(w, "TLS 1.3 only", http.StatusUpgradeRequired)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	home := r.URL.Query().Get(cloudwire.AppHomeParam)
	if !cloudwire.ValidHome(home) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if host, ours := s.owner(home); !ours {
		onceWrongShard.Inc()
		w.Header().Set(cloudwire.ShardHeader, host)
		w.WriteHeader(cloudwire.StatusWrongShard)
		return
	}
	// The watch sends no Origin. A browser always does, and has no business
	// here.
	if r.Header.Get("Origin") != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/octet-stream" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(cloudwire.OnceAnswerWithin)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
	msg1, err := io.ReadAll(io.LimitReader(r.Body, cloudwire.OnceMessage1MaxBytes+1))
	if err != nil || len(msg1) == 0 || len(msg1) > cloudwire.OnceMessage1MaxBytes {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !s.once.enterProcess() {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	defer s.once.leaveProcess()
	start := time.Now()
	body, status := s.answerOnce(r.Context(), home, msg1)
	onceHandshake.Since(start)
	if status != http.StatusOK {
		s.log.Debug("one-shot read refused", "status", status)
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(body)
}

// answerOnce runs the handshake and returns the answer body, or the status
// that refuses it.
func (s *Server) answerOnce(ctx context.Context, home string, msg1 []byte) ([]byte, int) {
	hs, err := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: s.key, Prologue: cloudwire.OncePrologue(home),
		Ephemeral: s.onceEphemeral})
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	payload, err := hs.ReadMessage(msg1)
	if err != nil {
		// Another service key, or another home in the prologue than in the
		// query. Neither says anything about the home.
		return nil, http.StatusForbidden
	}
	env, err := cloudwire.DecodeEnvelope(payload)
	if err != nil || len(env.Sig) != 0 || !slices.Contains(cloudwire.OnceMessages, env.T) {
		return nil, http.StatusBadRequest
	}
	dev, err := s.store.For(store.Principal{Kind: store.Device, Home: home, DeviceKey: hs.RemoteStatic()})
	if err != nil {
		return nil, http.StatusForbidden
	}
	// x is a watch's, and needs the roster's tun, as a phone's tunnel does,
	// so commands work with the copy off. The rest needs the copy: an
	// effective scope.
	if env.T == cloudwire.MsgX {
		if d := dev.Device(); !d.Tun || d.Role != protocol.RoleWatch {
			return nil, http.StatusForbidden
		}
	} else if len(dev.Scopes()) == 0 {
		return nil, http.StatusForbidden
	}
	release, ok := s.once.enter(home, hs.RemoteStatic(), s.now())
	if !ok {
		return nil, http.StatusTooManyRequests
	}
	defer release()

	reply, rest, status := s.onceReply(ctx, home, dev, env)
	if status != http.StatusOK {
		return nil, status
	}
	msg2, err := hs.WriteMessage(reply)
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	messages := [][]byte{msg2}
	if len(rest) > 0 {
		keys, err := hs.Split()
		if err != nil {
			return nil, http.StatusInternalServerError
		}
		tr := appwire.NewTransport(keys)
		for _, e := range rest {
			frame, err := cloudwire.EncodeFrame(e)
			if err != nil {
				return nil, http.StatusInternalServerError
			}
			sealed, err := tr.Encrypt(frame)
			if err != nil {
				return nil, http.StatusInternalServerError
			}
			messages = append(messages, sealed)
		}
	}
	body, err := cloudwire.OnceAnswer(messages...)
	if err != nil {
		return nil, http.StatusInternalServerError
	}
	return body, http.StatusOK
}

// onceReply is message 2's payload and, for a read, the envelopes to follow
// it. dev is the roster entry store.For matched, never anything the message
// says.
func (s *Server) onceReply(ctx context.Context, home string, dev *store.Handle, env cloudwire.Envelope) ([]byte, [][]byte, int) {
	switch env.T {
	case cloudwire.MsgRead:
		var rd cloudwire.Read
		if err := cloudwire.Unmarshal(env.B, &rd); err != nil {
			return nil, nil, http.StatusBadRequest
		}
		snap, err := dev.Snapshot()
		if err != nil {
			return nil, nil, http.StatusForbidden
		}
		// What the watch holds stays out, and so does an envelope too large
		// to follow in one Noise message, so more counts exactly what
		// follows.
		snap.Envelopes = slices.DeleteFunc(snap.Envelopes, func(e []byte) bool {
			return rd.Have.Covers(e) || cloudwire.HeaderBytes+len(e)+appwire.TransportOverhead > maxNoiseMessage
		})
		payload, rest, err := snapshotPayload(snap, s.onceMessage2)
		if err != nil {
			return nil, nil, http.StatusInternalServerError
		}
		if rd.Hz >= cloudwire.HzLooking {
			s.watchOnce(home)
		}
		return payload, rest, http.StatusOK
	case cloudwire.MsgTokenGet:
		if s.Tokens == nil {
			return nil, nil, http.StatusNotImplemented
		}
		tok, err := s.Tokens.Issue(home, dev.Device())
		switch {
		case errors.Is(err, store.ErrDenied):
			// Shut out between admission and the stored token.
			return nil, nil, http.StatusForbidden
		case err != nil:
			return nil, nil, http.StatusInternalServerError
		}
		payload, err := cloudwire.Unsigned(cloudwire.MsgToken, tok)
		if err != nil {
			return nil, nil, http.StatusInternalServerError
		}
		return payload, nil, http.StatusOK
	case cloudwire.MsgPushRegister, cloudwire.MsgPushUnregister:
		if s.Push == nil {
			return nil, nil, http.StatusNotImplemented
		}
		var err error
		if env.T == cloudwire.MsgPushRegister {
			var r cloudwire.PushRegister
			if cloudwire.Unmarshal(env.B, &r) != nil {
				return nil, nil, http.StatusBadRequest
			}
			err = s.Push.Register(home, dev.Device(), dev.Scopes(), r)
		} else {
			var r cloudwire.PushUnregister
			if cloudwire.Unmarshal(env.B, &r) != nil {
				return nil, nil, http.StatusBadRequest
			}
			err = s.Push.Unregister(home, dev.Device(), r)
		}
		// A registration the device may not make stores nothing and is
		// answered as the app session answers it: without a word.
		if pushed(err) != nil {
			return nil, nil, http.StatusInternalServerError
		}
		return nil, nil, http.StatusOK
	case cloudwire.MsgX:
		var x cloudwire.AppX
		if cloudwire.Unmarshal(env.B, &x) != nil || len(x.D) > cloudwire.XDataMax {
			return nil, nil, http.StatusBadRequest
		}
		// No box, or no answer from it, is an empty d, never an error.
		var d []byte
		if s.Exchange != nil {
			d = s.Exchange.Exchange(ctx, home, dev.Device().ID, x.D)
		}
		payload, err := cloudwire.Unsigned(cloudwire.MsgX, cloudwire.AppX{D: d})
		if err != nil {
			return nil, nil, http.StatusInternalServerError
		}
		return payload, nil, http.StatusOK
	}
	return nil, nil, http.StatusBadRequest
}
