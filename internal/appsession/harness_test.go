package appsession

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// A home with a box key, a roster with an owner and a viewer, and a TLS
// server answering /v1/app the way ftwcloudd does.
type harness struct {
	t       testing.TB
	store   *store.Store
	reg     *registry.Registry
	app     *Server
	srv     *httptest.Server
	watch   *watchCount
	noise   appwire.KeyPair
	boxKey  *ecdsa.PrivateKey
	home    string
	box     *store.Handle
	owner   appwire.KeyPair
	viewer  appwire.KeyPair
	seq     uint64
	rosterN uint64
	boot    []byte
	// shift moves the store's clock, in nanoseconds.
	shift *atomic.Int64
}

type watchCount struct {
	mu    sync.Mutex
	homes []string
}

func (w *watchCount) Watch(home string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.homes = append(w.homes, home)
}

func (w *watchCount) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.homes)
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	shift := &atomic.Int64{}
	st := store.New(func() time.Time { return time.Now().Add(time.Duration(shift.Load())) })
	st.UseSuspensions(reg.Suspended)
	noise, _ := appwire.GenerateKeyPair()
	w := &watchCount{}
	app := New(st, reg, w, noise, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	mux.Handle("/v1/app", app)
	mux.HandleFunc("/v1/app/once", app.ServeOnce)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	boxKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&boxKey.PublicKey)
	home := cloudwire.HomeID(pk)
	box, err := st.For(store.Principal{Kind: store.Box, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	box.Connected()
	if err := reg.Claim(home, pk, time.Now()); err != nil {
		t.Fatal(err)
	}
	owner, _ := appwire.GenerateKeyPair()
	viewer, _ := appwire.GenerateKeyPair()
	h := &harness{t: t, store: st, reg: reg, app: app, srv: srv, watch: w, noise: noise, boxKey: boxKey,
		home: home, box: box, owner: owner, viewer: viewer, boot: bytes.Repeat([]byte{0xb0}, cloudwire.BootBytes), shift: shift}
	h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead, protocol.ScopePlanRead)
	return h
}

func (h *harness) devices(ownerEpoch, viewerEpoch uint64) []cloudwire.Device {
	return []cloudwire.Device{
		{ID: "owner", Key: h.owner.Public(), Role: "owner", Scopes: protocol.CloudScopes, Epoch: ownerEpoch},
		{ID: "viewer", Key: h.viewer.Public(), Role: "viewer", Scopes: []string{protocol.ScopeLiveRead}, Epoch: viewerEpoch},
	}
}

func (h *harness) setRoster(devices []cloudwire.Device, grant ...string) {
	h.rosterN++
	r := &cloudwire.Roster{RosterSeq: h.rosterN, TTLS: 86_400, Devices: devices,
		Grant: cloudwire.Grant{ID: make([]byte, 16), Scopes: grant, Purposes: []string{protocol.CloudPurposeServe}, Controller: "sourceful"}}
	if !h.box.SetRoster(r) {
		h.t.Fatal("roster refused")
	}
	epochs := map[string]uint64{}
	for _, d := range devices {
		epochs[d.ID] = d.Epoch
	}
	if err := h.reg.PruneSuspensions(h.home, epochs); err != nil {
		h.t.Fatal(err)
	}
}

// put signs a body as the box and holds it, as the uplink does.
func (h *harness) put(t string, body func(cloudwire.Header) any, table bool) []byte {
	h.t.Helper()
	h.seq++
	hdr := cloudwire.Header{Seq: h.seq, Boot: h.boot, UptimeMs: int64(60_000 + h.seq*100)}
	env, err := cloudwire.Seal(h.boxKey, h.home, t, body(hdr))
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := env.Encode()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := h.box.Put(t, raw, h.seq, table); err != nil {
		h.t.Fatal(err)
	}
	return raw
}

func (h *harness) live(table bool) []byte {
	return h.put(cloudwire.MsgLive, func(hdr cloudwire.Header) any {
		l := cloudwire.Live{Header: hdr, Fields: map[string]int64{"2": 1800}, SrcRev: 1, Ages: map[string]int64{"m": 400}}
		if table {
			l.Sources = map[string]cloudwire.Source{"m": {Kind: "driver", State: protocol.SourceLive, StaleAfterMs: 10_000}}
			l.FieldSources = map[string][]string{"2": {"m"}}
		}
		return l
	}, table)
}

func (h *harness) plan() []byte {
	return h.put(cloudwire.MsgPlan, func(hdr cloudwire.Header) any {
		return struct {
			cloudwire.Header
			DecisionID string `cbor:"decisionId"`
		}{hdr, "d1"}
	}, false)
}

func (h *harness) hb() []byte {
	return h.put(cloudwire.MsgHB, func(hdr cloudwire.Header) any {
		return cloudwire.HB{Header: hdr, Clock: cloudwire.ClockNTP, SrcRev: 1, LiveSeq: h.seq - 1}
	}, false)
}

// phone is a Go client of /v1/app.
type phone struct {
	t    testing.TB
	conn *websocket.Conn
	tr   *appwire.Transport
	snap cloudwire.Snapshot
}

type dialOpts struct {
	key      appwire.KeyPair
	service  []byte // the service key the phone pins; nil uses the harness's
	home     string // query; "" uses the harness's
	prologue string // home in the prologue; "" uses query
	hz       int
}

// dial runs the handshake. It returns the close code when the service refuses
// before message 2.
func (h *harness) dial(o dialOpts) (*phone, int, error) {
	h.t.Helper()
	if o.service == nil {
		o.service = h.noise.Public()
	}
	if o.home == "" {
		o.home = h.home
	}
	if o.prologue == "" {
		o.prologue = o.home
	}
	d := websocket.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} //nolint:gosec // the test's own server
	url := strings.Replace(h.srv.URL, "https://", "wss://", 1) + "/v1/app?home=" + o.home
	conn, _, err := d.Dial(url, nil)
	if err != nil {
		return nil, 0, err
	}
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: o.key, RemoteStatic: o.service, Prologue: cloudwire.AppPrologue(o.prologue)})
	if err != nil {
		h.t.Fatal(err)
	}
	now, _ := cloudwire.Unsigned(cloudwire.MsgNow, cloudwire.Now{Hz: o.hz})
	msg1, _ := init.WriteMessage(now)
	if err := conn.WriteMessage(websocket.BinaryMessage, msg1); err != nil {
		return nil, 0, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, msg2, err := conn.ReadMessage()
	if err != nil {
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			conn.Close()
			return nil, ce.Code, nil
		}
		return nil, 0, err
	}
	payload, err := init.ReadMessage(msg2)
	if err != nil {
		h.t.Fatalf("message 2: %v", err)
	}
	snap, err := cloudwire.ParseSnapshot(payload)
	if err != nil {
		h.t.Fatalf("snapshot: %v", err)
	}
	keys, _ := init.Split()
	p := &phone{t: h.t, conn: conn, tr: appwire.NewTransport(keys), snap: snap}
	h.t.Cleanup(func() { conn.Close() })
	return p, 0, nil
}

func (h *harness) mustDial(o dialOpts) *phone {
	h.t.Helper()
	p, code, err := h.dial(o)
	if err != nil || code != 0 {
		h.t.Fatalf("dial: code %d, %v", code, err)
	}
	return p
}

// next reads one forwarded envelope, or the close code.
func (p *phone) next(within time.Duration) ([]byte, int) {
	p.t.Helper()
	_ = p.conn.SetReadDeadline(time.Now().Add(within))
	_, msg, err := p.conn.ReadMessage()
	if err != nil {
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			return nil, ce.Code
		}
		p.t.Fatalf("read: %v", err)
	}
	frame, err := p.tr.Decrypt(msg)
	if err != nil {
		p.t.Fatalf("decrypt: %v", err)
	}
	env, err := cloudwire.DecodeFrame(frame)
	if err != nil {
		p.t.Fatalf("frame: %v", err)
	}
	return env, 0
}

// closed waits for the service to end the session and returns its code.
func (p *phone) closed(within time.Duration) int {
	p.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if _, code := p.next(time.Until(deadline)); code != 0 {
			return code
		}
	}
	p.t.Fatal("the session stayed open")
	return 0
}

func (p *phone) send(t string, body any) {
	p.t.Helper()
	env, _ := cloudwire.Unsigned(t, body)
	frame, _ := cloudwire.EncodeFrame(env)
	msg, err := p.tr.Encrypt(frame)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := p.conn.WriteMessage(websocket.BinaryMessage, msg); err != nil {
		p.t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 3 s for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var _ http.Handler = (*Server)(nil)

func storePrincipal(h *harness, key appwire.KeyPair) store.Principal {
	return store.Principal{Kind: store.Device, Home: h.home, DeviceKey: key.Public()}
}
