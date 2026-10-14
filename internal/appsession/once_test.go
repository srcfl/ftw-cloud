package appsession

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/token"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// onceOpts is one one-shot read as a watch would post it, with the knobs a
// test turns.
type onceOpts struct {
	key      appwire.KeyPair
	service  []byte // the service key the watch pins; nil uses the harness's
	home     string // query; "" uses the harness's
	prologue string // home in the prologue; "" uses query
	t        string // message 1's type; "" is read
	body     any    // message 1's body; nil is read{hz: 0}
	// raw, when set, is posted instead of a handshake.
	raw []byte
	// header overrides, for the HTTP rules.
	method, contentType, origin string
}

// onceAnswer is what the watch makes of the answer.
type onceAnswer struct {
	status int
	// body is the raw answer, payload message 2's payload, and following
	// the envelopes after it, each as the box sent it.
	body      []byte
	payload   []byte
	following [][]byte
}

// once posts one one-shot read and opens the answer as the watch does.
func (h *harness) once(o onceOpts) onceAnswer {
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
	if o.t == "" {
		o.t = cloudwire.MsgRead
	}
	if o.body == nil {
		o.body = cloudwire.Read{Hz: cloudwire.HzAway}
	}
	if o.method == "" {
		o.method = http.MethodPost
	}
	if o.contentType == "" {
		o.contentType = "application/octet-stream"
	}
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: o.key, RemoteStatic: o.service,
		Prologue: cloudwire.OncePrologue(o.prologue)})
	if err != nil {
		h.t.Fatal(err)
	}
	msg1 := o.raw
	if msg1 == nil {
		payload, err := cloudwire.Unsigned(o.t, o.body)
		if err != nil {
			h.t.Fatal(err)
		}
		if msg1, err = init.WriteMessage(payload); err != nil {
			h.t.Fatal(err)
		}
	}
	req, _ := http.NewRequest(o.method, h.srv.URL+cloudwire.OncePath+"?"+cloudwire.AppHomeParam+"="+o.home, bytes.NewReader(msg1))
	req.Header.Set("Content-Type", o.contentType)
	if o.origin != "" {
		req.Header.Set("Origin", o.origin)
	}
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	a := onceAnswer{status: resp.StatusCode, body: body}
	if resp.StatusCode != http.StatusOK {
		if len(body) != 0 {
			h.t.Fatalf("a %d said %q", resp.StatusCode, body)
		}
		return a
	}
	if resp.Header.Get("Content-Type") != "application/octet-stream" || resp.Header.Get("Cache-Control") != "no-store" {
		h.t.Fatalf("answer headers %v", resp.Header)
	}
	parts, err := cloudwire.SplitOnceAnswer(body)
	if err != nil {
		h.t.Fatal(err)
	}
	if a.payload, err = init.ReadMessage(parts[0]); err != nil {
		h.t.Fatalf("message 2: %v", err)
	}
	keys, _ := init.Split()
	tr := appwire.NewTransport(keys)
	for _, m := range parts[1:] {
		frame, err := tr.Decrypt(m)
		if err != nil {
			h.t.Fatal(err)
		}
		env, err := cloudwire.DecodeFrame(frame)
		if err != nil {
			h.t.Fatal(err)
		}
		a.following = append(a.following, env)
	}
	return a
}

// snapshot reads a read's message 2 and joins what followed it.
func (a onceAnswer) snapshot(t *testing.T) (cloudwire.Snapshot, [][]byte) {
	t.Helper()
	snap, err := cloudwire.ParseSnapshot(a.payload)
	if err != nil {
		t.Fatal(err)
	}
	if snap.More != len(a.following) {
		t.Fatalf("more says %d, %d followed", snap.More, len(a.following))
	}
	all := make([][]byte, 0, len(snap.Envelopes)+len(a.following))
	for _, e := range snap.Envelopes {
		all = append(all, e)
	}
	return snap, append(all, a.following...)
}

// addWatch puts a watch under the owner in the roster, as the box lists
// one: role watch and its own key, with the scopes the box derives.
func (h *harness) addWatch(watch appwire.KeyPair, grant ...string) {
	devices := append(h.devices(1, 1), cloudwire.Device{ID: "watch", Key: watch.Public(), Role: "watch",
		Scopes: []string{protocol.ScopeLiveRead, protocol.ScopePlanRead, protocol.ScopeEventsRead}, Epoch: 1})
	h.setRoster(devices, grant...)
}

// A read answers with the app session's snapshot, as the box's own bytes,
// less what the watch already holds.
func TestAOnceReadCarriesTheBoxsBytesLessWhatTheWatchHolds(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.ScopeLiveRead, protocol.ScopePlanRead)
	full := h.live(true)
	plan := h.plan()
	delta := h.live(false)
	hb := h.hb()

	a := h.once(onceOpts{key: watch})
	if a.status != http.StatusOK {
		t.Fatalf("read: %d", a.status)
	}
	snap, all := a.snapshot(t)
	if !snap.Online || snap.LastSeenMs == 0 {
		t.Fatalf("snapshot %+v", snap)
	}
	want := [][]byte{full, plan, delta, hb}
	if len(all) != len(want) {
		t.Fatalf("read %d envelopes", len(all))
	}
	for i := range want {
		if !bytes.Equal(all[i], want[i]) {
			t.Fatalf("envelope %d is not the box's bytes", i)
		}
		verify(t, &h.boxKey.PublicKey, h.home, all[i])
	}

	// The watch holds the full live and the plan: only what is newer comes.
	have := cloudwire.Have{Boot: h.boot, Seq: map[string]uint64{cloudwire.MsgLive: 1, cloudwire.MsgPlan: 2}}
	a = h.once(onceOpts{key: watch, body: cloudwire.Read{Have: have}})
	if _, all = a.snapshot(t); len(all) != 2 || !bytes.Equal(all[0], delta) || !bytes.Equal(all[1], hb) {
		t.Fatalf("with have, read %d envelopes", len(all))
	}
	// A have from another boot covers nothing.
	have.Boot = bytes.Repeat([]byte{0xb1}, cloudwire.BootBytes)
	if _, all = h.once(onceOpts{key: watch, body: cloudwire.Read{Have: have}}).snapshot(t); len(all) != 4 {
		t.Fatalf("a have from another boot left out %d", 4-len(all))
	}
}

// Envelopes that do not fit in message 2 follow it, in rising seq.
func TestAOnceReadSpillsIntoTransportMessages(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.ScopeLiveRead)
	full := h.live(true)
	delta := h.live(false)
	hb := h.hb()
	probe, _ := cloudwire.SnapshotPayload([][]byte{full}, 0, true, 2)
	h.app.onceMessage2 = len(probe) + appwire.Message2Overhead + 20
	a := h.once(onceOpts{key: watch})
	snap, all := a.snapshot(t)
	if len(snap.Envelopes) != 1 || len(a.following) != 2 || !bytes.Equal(all[1], delta) || !bytes.Equal(all[2], hb) {
		t.Fatalf("message 2 held %d, %d followed", len(snap.Envelopes), len(a.following))
	}
}

// ADR 0009: the one-shot read admits exactly the devices /v1/app admits,
// through the same table of cases.
func TestOnceAdmitsExactlyWhatTheAppSessionAdmits(t *testing.T) {
	stranger, _ := appwire.GenerateKeyPair()
	otherService, _ := appwire.GenerateKeyPair()
	const otherHome = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	type kase struct {
		name  string
		setup func(h *harness, watch appwire.KeyPair) (appwire.KeyPair, dialOpts)
		admit bool
	}
	plain := func(pick func(h *harness, watch appwire.KeyPair) appwire.KeyPair) func(*harness, appwire.KeyPair) (appwire.KeyPair, dialOpts) {
		return func(h *harness, watch appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			k := pick(h, watch)
			return k, dialOpts{key: k}
		}
	}
	cases := []kase{
		{"the owner", plain(func(h *harness, _ appwire.KeyPair) appwire.KeyPair { return h.owner }), true},
		{"a viewer", plain(func(h *harness, _ appwire.KeyPair) appwire.KeyPair { return h.viewer }), true},
		{"a watch", plain(func(_ *harness, w appwire.KeyPair) appwire.KeyPair { return w }), true},
		{"a key the roster lacks", plain(func(*harness, appwire.KeyPair) appwire.KeyPair { return stranger }), false},
		{"another service key", func(_ *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			return w, dialOpts{key: w, service: otherService.Public()}
		}, false},
		{"another home in the prologue", func(_ *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			return w, dialOpts{key: w, prologue: otherHome}
		}, false},
		{"a home the service lacks", func(_ *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			return w, dialOpts{key: w, home: otherHome}
		}, false},
		{"a suspended watch", func(h *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			_ = h.reg.Suspend(h.home, "watch", 1, time.Now())
			return w, dialOpts{key: w}
		}, false},
		{"a watch the roster dropped", func(h *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead)
			return w, dialOpts{key: w}
		}, false},
		{"a roster that ran out", func(h *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			h.shift.Store(int64(24*time.Hour + time.Second))
			return w, dialOpts{key: w}
		}, false},
		{"a purged home", func(h *harness, w appwire.KeyPair) (appwire.KeyPair, dialOpts) {
			h.box.Delete()
			return w, dialOpts{key: w}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			watch, _ := appwire.GenerateKeyPair()
			h.addWatch(watch, protocol.ScopeLiveRead)
			h.live(true)
			key, o := c.setup(h, watch)
			_, code, err := h.dial(o)
			if err != nil {
				t.Fatal(err)
			}
			a := h.once(onceOpts{key: key, service: o.service, home: o.home, prologue: o.prologue})
			appAdmits, onceAdmits := code == 0, a.status == http.StatusOK
			if appAdmits != c.admit || onceAdmits != c.admit {
				t.Fatalf("/v1/app closed with %d, /v1/app/once said %d; want admitted = %v", code, a.status, c.admit)
			}
			if !c.admit && (code != cloudwire.CloseDenied || a.status != http.StatusForbidden) {
				t.Fatalf("refusals: %d and %d", code, a.status)
			}
		})
	}
}

// ADR 0009: a watch the roster drops is refused within a second of that
// roster arriving.
func TestAWatchTheRosterDropsIsRefusedWithinASecond(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.ScopeLiveRead)
	h.live(true)
	if a := h.once(onceOpts{key: watch}); a.status != http.StatusOK {
		t.Fatalf("before: %d", a.status)
	}
	arrived := time.Now()
	h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead)
	if a := h.once(onceOpts{key: watch}); a.status != http.StatusForbidden {
		t.Fatalf("after the roster dropped it: %d", a.status)
	}
	if took := time.Since(arrived); took > time.Second {
		t.Fatalf("the refusal came %v after the roster", took)
	}
}

// Message 1 may carry read, token.get, push.register and push.unregister.
// Everything else, an owner's suspend among them, gets 400 before message 2,
// and so does a signed envelope.
func TestOnceRefusesOtherMessages(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	for _, c := range []struct {
		t    string
		body any
	}{
		{cloudwire.MsgSuspend, cloudwire.Suspend{DeviceID: "viewer"}},
		{cloudwire.MsgUnsuspend, cloudwire.Suspend{DeviceID: "viewer"}},
		{cloudwire.MsgNow, cloudwire.Now{Hz: 1}},
		{cloudwire.MsgWatch, cloudwire.Watch{Hz: 1}},
		{"tiles.get", map[string]any{"have": map[string]string{}}},
	} {
		if a := h.once(onceOpts{key: h.owner, t: c.t, body: c.body}); a.status != http.StatusBadRequest {
			t.Errorf("%s: %d", c.t, a.status)
		}
	}
	if h.reg.Suspended(h.home, "viewer", 1) {
		t.Fatal("a one-shot read suspended a device")
	}
	init, _ := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: h.owner, RemoteStatic: h.noise.Public(),
		Prologue: cloudwire.OncePrologue(h.home)})
	b, _ := cloudwire.Marshal(cloudwire.Read{})
	signed, _ := cloudwire.Envelope{T: cloudwire.MsgRead, B: b, Sig: bytes.Repeat([]byte{1}, 64)}.Encode()
	msg1, _ := init.WriteMessage(signed)
	if a := h.once(onceOpts{key: h.owner, raw: msg1}); a.status != http.StatusBadRequest {
		t.Fatalf("a signed message 1: %d", a.status)
	}
	if a := h.once(onceOpts{key: h.owner, body: "not a read"}); a.status != http.StatusBadRequest {
		t.Fatalf("an unreadable read: %d", a.status)
	}
}

func TestOnceHTTPRules(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	for name, c := range map[string]struct {
		o    onceOpts
		want int
	}{
		"GET":                  {onceOpts{key: h.owner, method: http.MethodGet}, http.StatusMethodNotAllowed},
		"a browser's Origin":   {onceOpts{key: h.owner, origin: "https://example.com"}, http.StatusForbidden},
		"another content type": {onceOpts{key: h.owner, contentType: "application/json"}, http.StatusUnsupportedMediaType},
		"no home":              {onceOpts{key: h.owner, home: "not-a-home"}, http.StatusBadRequest},
		"an empty body":        {onceOpts{key: h.owner, raw: []byte{}}, http.StatusBadRequest},
		"message 1 over 4 KiB": {onceOpts{key: h.owner, raw: make([]byte, cloudwire.OnceMessage1MaxBytes+1)}, http.StatusBadRequest},
		"noise garbage":        {onceOpts{key: h.owner, raw: bytes.Repeat([]byte{7}, 200)}, http.StatusForbidden},
	} {
		if a := h.once(c.o); a.status != c.want {
			t.Errorf("%s: %d, want %d", name, a.status, c.want)
		}
	}
	// A large message 1 that still fits is read.
	big := cloudwire.Read{Have: cloudwire.Have{Boot: h.boot, Seq: map[string]uint64{}}}
	for i := range 150 {
		big.Have.Seq[strings.Repeat("x", 10)+string(rune('a'+i%26))+string(rune('a'+i/26))] = 1
	}
	if a := h.once(onceOpts{key: h.owner, body: big}); a.status != http.StatusOK {
		t.Fatalf("a 3 KiB message 1: %d", a.status)
	}
}

// One read at a time per device and 30 a minute; past that, 429. Another
// device of the home is not held back.
func TestOnceLimitsADevicesReads(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	for i := range cloudwire.OnceReadsPerMinute {
		if a := h.once(onceOpts{key: h.owner}); a.status != http.StatusOK {
			t.Fatalf("read %d: %d", i, a.status)
		}
	}
	if a := h.once(onceOpts{key: h.owner}); a.status != http.StatusTooManyRequests {
		t.Fatalf("read 31 in a minute: %d", a.status)
	}
	if a := h.once(onceOpts{key: h.viewer}); a.status != http.StatusOK {
		t.Fatalf("another device: %d", a.status)
	}
}

func TestOnceLimitsCountInFlight(t *testing.T) {
	l := onceLimits{homes: map[string]int{}, devices: map[string]*onceDevice{}}
	now := time.Unix(1_791_820_800, 0)
	key := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	release, ok := l.enter("h1", key(1), now)
	if !ok {
		t.Fatal("the first read was refused")
	}
	if _, ok := l.enter("h1", key(1), now); ok {
		t.Fatal("a device had two reads open")
	}
	release()
	if r, ok := l.enter("h1", key(1), now); !ok {
		t.Fatal("a device could not read after its read ended")
	} else {
		r()
	}
	var open []func()
	for i := range MaxOncePerHome {
		r, ok := l.enter("h1", key(byte(10+i)), now)
		if !ok {
			t.Fatalf("read %d of the home refused", i)
		}
		open = append(open, r)
	}
	if _, ok := l.enter("h1", key(99), now); ok {
		t.Fatal("a home had more reads open than it may")
	}
	if r, ok := l.enter("h2", key(99), now); !ok {
		t.Fatal("one home's reads held back another's")
	} else {
		r()
	}
	for _, r := range open {
		r()
	}
	for range MaxOnceInFlight {
		if !l.enterProcess() {
			t.Fatal("the process refused below its limit")
		}
	}
	if l.enterProcess() {
		t.Fatal("the process took more reads than it may")
	}
	for range MaxOnceInFlight {
		l.leaveProcess()
	}
	if inFlight, _ := l.held(); inFlight != 0 {
		t.Fatalf("%d reads still counted", inFlight)
	}
	// A minute later the devices that read are forgotten.
	r, _ := l.enter("h3", key(1), now.Add(2*time.Minute))
	r()
	if _, devices := l.held(); devices != 1 {
		t.Fatalf("%d devices still known", devices)
	}
}

// ADR 0009: after an answer the service holds no session and no Noise state
// for that read. A home's sessions are all still there to open.
func TestOnceKeepsNothingAfterTheAnswer(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	for range 5 {
		if a := h.once(onceOpts{key: h.owner, body: cloudwire.Read{Hz: cloudwire.HzLooking}}); a.status != http.StatusOK {
			t.Fatalf("read: %d", a.status)
		}
	}
	if inFlight, _ := h.app.once.held(); inFlight != 0 {
		t.Fatalf("%d reads still counted after their answers", inFlight)
	}
	h.app.mu.Lock()
	looking := len(h.app.looking)
	h.app.mu.Unlock()
	if looking != 0 {
		t.Fatal("a one-shot read left the home looked at")
	}
	keys := make([]appwire.KeyPair, store.MaxSessionsPerHome)
	devices := h.devices(1, 1)
	for i := range keys {
		keys[i], _ = appwire.GenerateKeyPair()
		devices = append(devices, cloudwire.Device{ID: "phone-" + string(rune('a'+i)), Key: keys[i].Public(),
			Role: "viewer", Scopes: []string{protocol.ScopeLiveRead}, Epoch: 1})
	}
	h.setRoster(devices, protocol.ScopeLiveRead)
	for i, k := range keys {
		x, err := h.store.For(store.Principal{Kind: store.Device, Home: h.home, DeviceKey: k.Public()})
		if err != nil {
			t.Fatal(err)
		}
		_, sess, err := x.Open()
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		defer sess.Close()
	}
}

// hz 1 asks the box for one-second updates, as a looking phone does; hz 0
// leaves it as it is.
func TestOnceHzAsksTheBoxToHurry(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	h.once(onceOpts{key: h.owner})
	if h.watch.count() != 0 {
		t.Fatal("hz 0 asked the box")
	}
	h.once(onceOpts{key: h.owner, body: cloudwire.Read{Hz: cloudwire.HzLooking}})
	waitFor(t, "hz 1 to ask the box", func() bool { return h.watch.count() == 1 })
	h.once(onceOpts{key: h.owner, home: "aaaaaaaaaaaaaaaaaaaaaaaaaa", body: cloudwire.Read{Hz: cloudwire.HzLooking}})
	time.Sleep(50 * time.Millisecond)
	if h.watch.count() != 1 {
		t.Fatal("a refused read asked a box")
	}
	// A box that comes back within the minute is asked again; after it,
	// not.
	h.app.BoxConnected(h.home)
	if h.watch.count() != 2 {
		t.Fatalf("a box back within the minute was asked %d times in all", h.watch.count())
	}
	h.app.now = func() time.Time { return time.Now().Add(61 * time.Second) }
	h.app.BoxConnected(h.home)
	if h.watch.count() != 2 {
		t.Fatal("a box back after the minute was asked")
	}
}

// Freshness stays the box's: an hour after the box went quiet, a read
// carries when it was last seen and no readings.
func TestAOnceReadAfterAnHourWithoutTheBoxCarriesNoReadings(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	h.hb()
	gen := h.box.Connected()
	h.box.Disconnected(gen)
	h.shift.Store(int64(store.ReadingsKeptFor + time.Second))
	snap, all := h.once(onceOpts{key: h.owner}).snapshot(t)
	if len(all) != 0 || snap.Online || snap.LastSeenMs == 0 {
		t.Fatalf("after an hour: %d envelopes, online %v, last seen %d", len(all), snap.Online, snap.LastSeenMs)
	}
}

// ADR 0009: a watch gets its own token over the one-shot read. It reads
// live, prices and hb, and nothing else.
func TestAWatchTokenReadsLivePricesAndHB(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.CloudScopes...)
	read := h.tokens(t)
	full := h.live(true)
	h.plan()
	prices := h.put(cloudwire.MsgPrices, func(hdr cloudwire.Header) any {
		return cloudwire.Prices{Header: hdr, SpotMinor: []*int64{}, TotalMinor: []*int64{}}
	}, false)
	h.put(cloudwire.MsgLP, func(hdr cloudwire.Header) any {
		return cloudwire.LP{Header: hdr, Loadpoints: []cloudwire.Loadpoint{}, Feedback: []cloudwire.Feedback{}}
	}, false)
	h.put(cloudwire.MsgEvent, func(hdr cloudwire.Header) any {
		return cloudwire.Event{Header: hdr, EventID: "e", Kind: "k", Severity: cloudwire.SeverityInfo, Args: map[string]string{}}
	}, false)
	hb := h.hb()

	a := h.once(onceOpts{key: watch, t: cloudwire.MsgTokenGet, body: struct{}{}})
	if a.status != http.StatusOK || len(a.following) != 0 {
		t.Fatalf("token.get: %d", a.status)
	}
	env, err := cloudwire.DecodeEnvelope(a.payload)
	if err != nil || env.T != cloudwire.MsgToken || len(env.Sig) != 0 {
		t.Fatalf("message 2 is %q", env.T)
	}
	var tok cloudwire.Token
	if err := cloudwire.Unmarshal(env.B, &tok); err != nil || tok.ExpiresInS != int64(token.Life/time.Second) {
		t.Fatalf("token %+v %v", tok, err)
	}
	code, body := read(tok.Token)
	if code != http.StatusOK {
		t.Fatalf("the watch's token read %d", code)
	}
	var now token.Now
	if err := cloudwire.Unmarshal(body, &now); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{full, prices, hb}
	if len(now.Envelopes) != len(want) {
		t.Fatalf("the watch's token read %d envelopes", len(now.Envelopes))
	}
	for i := range want {
		if !bytes.Equal(now.Envelopes[i], want[i]) {
			t.Fatalf("envelope %d is not the box's", i)
		}
	}
	// The watch's token is its own: the owner's next token leaves it be.
	if _, err := h.app.Tokens.Issue(h.home, h.devices(1, 1)[0]); err != nil {
		t.Fatal(err)
	}
	if code, _ := read(tok.Token); code != http.StatusOK {
		t.Fatalf("the owner's new token killed the watch's: %d", code)
	}
}

// A watch registers its APNs tokens with app watch over the one-shot read,
// and message 2 is empty once the change is stored.
func TestAWatchRegistersForPushOverOnce(t *testing.T) {
	h := newHarness(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.ScopeLiveRead, protocol.ScopeEventsRead)
	h.app.Push = push.New(h.reg, nil, nil)
	for _, kind := range []string{cloudwire.PushKindAlert, push.KindWidgets} {
		a := h.once(onceOpts{key: watch, t: cloudwire.MsgPushRegister, body: cloudwire.PushRegister{
			APNsToken: []byte("watch-" + kind), Environment: cloudwire.PushSandbox, Kind: kind, App: cloudwire.PushAppWatch}})
		if a.status != http.StatusOK || len(a.payload) != 0 {
			t.Fatalf("register %s: %d, %d bytes", kind, a.status, len(a.payload))
		}
		regs, _ := h.reg.PushRegs(h.home, kind)
		if len(regs) != 1 || regs[0].DeviceID != "watch" || regs[0].App != cloudwire.PushAppWatch {
			t.Fatalf("%s registrations %+v", kind, regs)
		}
	}
	a := h.once(onceOpts{key: watch, t: cloudwire.MsgPushUnregister, body: cloudwire.PushUnregister{APNsToken: []byte("watch-alert")}})
	if a.status != http.StatusOK {
		t.Fatalf("unregister: %d", a.status)
	}
	if regs, _ := h.reg.PushRegs(h.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatal("the watch's alert token stayed")
	}
	// A registration the watch may not make stores nothing and is answered
	// as the app session answers it.
	a = h.once(onceOpts{key: watch, t: cloudwire.MsgPushRegister, body: cloudwire.PushRegister{
		APNsToken: []byte("odd"), Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert, App: "tv"}})
	if a.status != http.StatusOK {
		t.Fatalf("an odd registration: %d", a.status)
	}
	if regs, _ := h.reg.PushRegs(h.home, cloudwire.PushKindAlert); len(regs) != 0 {
		t.Fatal("an odd app was registered")
	}
}

// Without a token or push service, those messages get 501 and a read still
// works.
func TestOnceWithoutTokensOrPush(t *testing.T) {
	h := newHarness(t)
	h.live(true)
	if a := h.once(onceOpts{key: h.owner, t: cloudwire.MsgTokenGet, body: struct{}{}}); a.status != http.StatusNotImplemented {
		t.Fatalf("token.get: %d", a.status)
	}
	if a := h.once(onceOpts{key: h.owner, t: cloudwire.MsgPushUnregister, body: cloudwire.PushUnregister{}}); a.status != http.StatusNotImplemented {
		t.Fatalf("push.unregister: %d", a.status)
	}
}

// The service logs no body, no home, no key and no token, whatever a read
// asks and however it ends.
func TestOnceLogsNoBodies(t *testing.T) {
	h := newHarness(t)
	var buf lockedBuffer
	h.app.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h.app.Push = push.New(h.reg, nil, h.app.log)
	_ = h.tokens(t)
	watch, _ := appwire.GenerateKeyPair()
	h.addWatch(watch, protocol.CloudScopes...)
	full := h.live(true)
	h.once(onceOpts{key: watch, body: cloudwire.Read{Hz: 1}})
	tokAnswer := h.once(onceOpts{key: watch, t: cloudwire.MsgTokenGet, body: struct{}{}})
	h.once(onceOpts{key: watch, t: cloudwire.MsgPushRegister, body: cloudwire.PushRegister{
		APNsToken: []byte("apns-token-canary"), Environment: cloudwire.PushSandbox, Kind: cloudwire.PushKindAlert, App: cloudwire.PushAppWatch}})
	h.once(onceOpts{key: watch, t: cloudwire.MsgSuspend, body: cloudwire.Suspend{DeviceID: "owner"}})
	stranger, _ := appwire.GenerateKeyPair()
	h.once(onceOpts{key: stranger})
	h.once(onceOpts{key: watch, raw: bytes.Repeat([]byte{7}, 200)})

	env, _ := cloudwire.DecodeEnvelope(tokAnswer.payload)
	var tok cloudwire.Token
	_ = cloudwire.Unmarshal(env.B, &tok)
	logged := buf.String()
	for name, secret := range map[string]string{
		"the home":       h.home,
		"the token":      tok.Token,
		"the APNs token": "apns-token-canary",
		"a reading":      string(full[len(full)-20:]),
		"the watch key":  string(watch.Public()),
	} {
		if secret != "" && strings.Contains(logged, secret) {
			t.Fatalf("the log holds %s:\n%s", name, logged)
		}
	}
	if !strings.Contains(logged, "one-shot read refused") {
		t.Fatalf("the log said nothing at debug level, so the test proves nothing:\n%s", logged)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestOnceRefusesPlainHTTP(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest(http.MethodPost, cloudwire.OncePath+"?home="+h.home, bytes.NewReader([]byte{1}))
	req.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	h.app.ServeOnce(w, req)
	if w.Code != http.StatusUpgradeRequired {
		t.Fatalf("plain HTTP: %d", w.Code)
	}
}
