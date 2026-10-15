package relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const (
	testEpoch = int64(500_000)
	handleA   = "ab0123456789abcdef0123456789abcd"
	handleB   = "cd0123456789abcdef0123456789abcd"
)

func testTime() time.Time { return time.UnixMilli(testEpoch * EpochMs).UTC() }

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func startRelay(t *testing.T, opts Options) (*Relay, *httptest.Server) {
	t.Helper()
	if opts.Log == nil {
		opts.Log = discardLog()
	}
	if opts.Now == nil {
		opts.Now = testTime
	}
	r := New(opts)
	srv := httptest.NewServer(r)
	t.Cleanup(func() {
		r.Close()
		srv.Close()
	})
	return r, srv
}

func wsBase(httpURL string) string { return "ws" + strings.TrimPrefix(httpURL, "http") }

func dial(t *testing.T, base string, epoch int64, handle, role string, hdr http.Header) *websocket.Conn {
	t.Helper()
	u := fmt.Sprintf("%s/r/%d/%s/%s", wsBase(base), epoch, handle, role)
	c, _, err := (&websocket.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(u, hdr)
	if err != nil {
		t.Fatalf("dial %s: %v", role, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func readMsg(t *testing.T, c *websocket.Conn) (int, []byte) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	kind, msg, err := c.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	return kind, msg
}

func expectClose(t *testing.T, c *websocket.Conn, code int, reason string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) {
		t.Fatalf("got %v, want close %d %q", err, code, reason)
	}
	if ce.Code != code || ce.Text != reason {
		t.Fatalf("close %d %q, want %d %q", ce.Code, ce.Text, code, reason)
	}
}

func TestWireConstantsMatchTheClients(t *testing.T) {
	if CloseBadJoin != 4400 || CloseEpoch != 4409 || CloseRotated != 4410 || CloseBusy != 4429 {
		t.Fatal("close codes drifted from the box and the webapp")
	}
	if CtrlReady != "ready" || CtrlGone != "gone" {
		t.Fatal("control words drifted")
	}
	if EpochMs != 3_600_000 || HandleChars != 32 || ExchangeIDBytes != 16 {
		t.Fatal("epoch, handle or exchange id drifted")
	}
	if exchangeOpenBytes != 608 || exchangeRequestBytes != 536 || exchangeMaxReply != 4096 {
		t.Fatal("exchange sizes drifted from the watch")
	}
	if CurrentEpoch(testTime()) != testEpoch {
		t.Fatalf("epoch = %d", CurrentEpoch(testTime()))
	}
	// Floor, not truncation toward zero. The app uses Math.floor.
	if CurrentEpoch(time.UnixMilli(-1)) != -1 {
		t.Fatal("a clock before 1970 disagreed with the app")
	}
}

func TestFramesPassThroughUnchangedAndStayInTheRoom(t *testing.T) {
	_, srv := startRelay(t, Options{})
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	app1 := dial(t, srv.URL, testEpoch, handleA, roleApp, http.Header{"Origin": {"https://webapp.example"}})
	app2 := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	other := dial(t, srv.URL, testEpoch, handleB, roleBox, nil)

	for _, c := range []*websocket.Conn{box, app1, app2} {
		kind, msg := readMsg(t, c)
		if kind != websocket.TextMessage || string(msg) != CtrlReady {
			t.Fatalf("ready: kind %d %q", kind, msg)
		}
	}

	payload := []byte("COMMAND-set_mode-watt-4242-\x00\xff")
	if err := app1.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
	kind, got := readMsg(t, box)
	if kind != websocket.BinaryMessage || !bytes.Equal(got, payload) {
		t.Fatalf("box got kind %d %q", kind, got)
	}

	// A read that times out leaves a gorilla connection unusable, so the
	// proof that a frame stayed in its room is the next frame each peer
	// does see: app2's first binary is the box's reply, not app1's command,
	// and the other room's box sees nothing before it is closed below.
	back := []byte{0x01, 0x02, 0x03, 0x00}
	if err := box.WriteMessage(websocket.BinaryMessage, back); err != nil {
		t.Fatal(err)
	}
	if _, got = readMsg(t, app1); !bytes.Equal(got, back) {
		t.Fatalf("app1 got %x", got)
	}
	if _, got = readMsg(t, app2); !bytes.Equal(got, back) {
		t.Fatalf("app2 got %x, a stream saw another stream", got)
	}

	// One stream leaving leaves the other side present. gone is the last one.
	_ = app1.Close()
	if err := app2.WriteMessage(websocket.BinaryMessage, []byte{9}); err != nil {
		t.Fatal(err)
	}
	if _, got = readMsg(t, box); !bytes.Equal(got, []byte{9}) {
		t.Fatalf("box after one stream left: %x", got)
	}
	_ = app2.Close()
	kind, msg := readMsg(t, box)
	if kind != websocket.TextMessage || string(msg) != CtrlGone {
		t.Fatalf("gone: kind %d %q", kind, msg)
	}
	_ = other.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := other.ReadMessage(); err == nil {
		t.Fatal("another session received the frame")
	}
}

func TestTheIncumbentBoxKeepsTheRoom(t *testing.T) {
	_, srv := startRelay(t, Options{})
	first := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	second := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	expectClose(t, second, CloseBusy, "uplink")

	app := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	if _, msg := readMsg(t, app); string(msg) != CtrlReady {
		t.Fatalf("app: %q", msg)
	}
	if _, msg := readMsg(t, first); string(msg) != CtrlReady {
		t.Fatalf("box: %q", msg)
	}
}

func TestJoinRefusalsUseTheRelayCloseCodes(t *testing.T) {
	_, srv := startRelay(t, Options{})
	cases := []struct {
		path   string
		code   int
		reason string
	}{
		{"/r/nope/" + handleA + "/box", CloseBadJoin, "join"},
		{"/r/" + fmt.Sprint(testEpoch) + "/ABCDEF0123456789ABCDEF0123456789/box", CloseBadJoin, "join"},
		{"/r/" + fmt.Sprint(testEpoch) + "/" + handleA + "/phone", CloseBadJoin, "join"},
		{"/r/" + fmt.Sprint(testEpoch+3) + "/" + handleA + "/box", CloseEpoch, fmt.Sprint(testEpoch)},
	}
	for _, c := range cases {
		conn, _, err := (&websocket.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(wsBase(srv.URL)+c.path, nil)
		if err != nil {
			t.Fatalf("%s: dial %v", c.path, err)
		}
		expectClose(t, conn, c.code, c.reason)
		_ = conn.Close()
	}
}

func TestTextIsNotRoutedAndADeadmanClaimIsConsumed(t *testing.T) {
	_, srv := startRelay(t, Options{})
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	app := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	_, _ = readMsg(t, box)
	_, _ = readMsg(t, app)

	id := "0123456789abcdef0123456789abcdef"
	if err := box.WriteMessage(websocket.TextMessage, []byte("deadman "+id)); err != nil {
		t.Fatal(err)
	}
	// The claim and the following frame share the box socket, so the frame
	// cannot arrive ahead of a claim that was routed by mistake.
	if err := box.WriteMessage(websocket.BinaryMessage, []byte{7}); err != nil {
		t.Fatal(err)
	}
	kind, msg := readMsg(t, app)
	if kind != websocket.BinaryMessage || !bytes.Equal(msg, []byte{7}) {
		t.Fatalf("the claim was routed: kind %d %q", kind, msg)
	}
	if err := app.WriteMessage(websocket.TextMessage, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	expectClose(t, app, CloseBadJoin, "binary only")
	// The box stays. A claim is not a reason to drop it, and neither is
	// some other peer's mistake.
	if err := box.WriteMessage(websocket.BinaryMessage, []byte{7}); err != nil {
		t.Fatal(err)
	}
}

func TestRoomLimits(t *testing.T) {
	_, srv := startRelay(t, Options{})
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	for i := 0; i < maxStreamsPerRoom; i++ {
		app := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
		_, _ = readMsg(t, app)
	}
	_, _ = readMsg(t, box)
	fifth := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	expectClose(t, fifth, CloseBusy, "streams")

	ex := dial(t, srv.URL, testEpoch, handleA, roleExchange, nil)
	second := dial(t, srv.URL, testEpoch, handleA, roleExchange, nil)
	expectClose(t, second, CloseBusy, "exchange")
	_ = ex.Close()
}

func TestAFrameAtTheSizeLimitPassesAndTheNextRateCloses(t *testing.T) {
	_, srv := startRelay(t, Options{})
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	app := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	_, _ = readMsg(t, box)
	_, _ = readMsg(t, app)

	big := bytes.Repeat([]byte{0x11}, maxFrameBytes)
	if err := app.WriteMessage(websocket.BinaryMessage, big); err != nil {
		t.Fatal(err)
	}
	if _, got := readMsg(t, box); !bytes.Equal(got, big) {
		t.Fatalf("got %d bytes", len(got))
	}
	for i := 1; i < frameCapacity; i++ {
		if err := app.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	// Drain so a slow reader is not why the next write fails.
	for i := 1; i < frameCapacity; i++ {
		_, _ = readMsg(t, box)
	}
	if err := app.WriteMessage(websocket.BinaryMessage, []byte{1}); err != nil {
		t.Fatal(err)
	}
	expectClose(t, app, CloseBusy, "rate")
}

func TestRotationIsSpreadAndANewRoomIsLeftAlone(t *testing.T) {
	clk := &clock{t: testTime()}
	r, srv := startRelay(t, Options{Now: clk.Now})
	low := "00000000000000000000000000000000"
	high := "ffffffffffffffffffffffffffffffff"
	early := dial(t, srv.URL, testEpoch, low, roleBox, nil)
	late := dial(t, srv.URL, testEpoch, high, roleBox, nil)
	lateApp := dial(t, srv.URL, testEpoch, high, roleApp, nil)
	if _, msg := readMsg(t, late); string(msg) != CtrlReady {
		t.Fatalf("late box: %q", msg)
	}
	if _, msg := readMsg(t, lateApp); string(msg) != CtrlReady {
		t.Fatalf("late app: %q", msg)
	}

	clk.Set(testTime().Add(time.Duration(EpochMs)*time.Millisecond + time.Millisecond))
	r.beat()
	expectClose(t, early, CloseRotated, fmt.Sprint(testEpoch+1))

	// The late room has not had its turn, so the peers already in it keep
	// passing frames. A new join of the old epoch is still a wrong epoch:
	// the handle is derived from the epoch, and a window there would park
	// a peer in a room its box will never register. Frankfurt answers with
	// the epoch to use.
	if err := lateApp.WriteMessage(websocket.BinaryMessage, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if _, got := readMsg(t, late); !bytes.Equal(got, []byte{4}) {
		t.Fatalf("late room dropped a frame before its turn: %x", got)
	}
	// Reading delivers the heartbeat's ping to both peers, so the next beat
	// rotates them instead of reaping a missed pong.
	if err := late.WriteMessage(websocket.BinaryMessage, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if _, got := readMsg(t, lateApp); !bytes.Equal(got, []byte{4}) {
		t.Fatalf("late app: %x", got)
	}
	conn, _, err := (&websocket.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(
		fmt.Sprintf("%s/r/%d/%s/app", wsBase(srv.URL), testEpoch, high), nil)
	if err != nil {
		t.Fatal(err)
	}
	expectClose(t, conn, CloseEpoch, fmt.Sprint(testEpoch+1))
	_ = conn.Close()

	// A room that joined the new hour is not evicted when the window ends.
	fresh := dial(t, srv.URL, testEpoch+1, handleA, roleBox, nil)
	freshApp := dial(t, srv.URL, testEpoch+1, handleA, roleApp, nil)
	_, _ = readMsg(t, fresh)
	_, _ = readMsg(t, freshApp)

	clk.Set(testTime().Add(time.Duration(EpochMs)*time.Millisecond + rotateSpread))
	r.beat()
	expectClose(t, late, CloseRotated, fmt.Sprint(testEpoch+1))
	// The uplink's close can say gone before the rotation close lands.
	// Both words are the relay's; the close code is the one a client acts on.
	_ = lateApp.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, msg, err := lateApp.ReadMessage()
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			if ce.Code != CloseRotated || ce.Text != fmt.Sprint(testEpoch+1) {
				t.Fatalf("close %d %q", ce.Code, ce.Text)
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if string(msg) != CtrlGone {
			t.Fatalf("late app got %q", msg)
		}
	}
	if err := freshApp.WriteMessage(websocket.BinaryMessage, []byte{5}); err != nil {
		t.Fatal(err)
	}
	if _, got := readMsg(t, fresh); !bytes.Equal(got, []byte{5}) {
		t.Fatal("a room on the new hour was rotated")
	}
}

func TestExchangeRoundTripIsBlind(t *testing.T) {
	_, srv := startRelay(t, Options{})
	_ = dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	ex := dial(t, srv.URL, testEpoch, handleA, roleExchange, nil)
	body := bytes.Repeat([]byte{0x5a}, exchangeRequestBytes)
	copy(body, []byte("COMMAND-set_mode"))
	reply := []byte("REPLY-not-parsed-\x00")

	type httpResult struct {
		code int
		body []byte
		hdr  http.Header
	}
	got := make(chan httpResult, 1)
	go func() {
		// Dial returns when the handshake completes, a moment before the
		// socket is in the room. A 501 in that gap is the watch's "try
		// again", not a missing box.
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x/"+fmt.Sprint(testEpoch)+"/"+handleA, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/octet-stream")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				got <- httpResult{code: -1}
				return
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			if (res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusNotFound) && i+1 < 50 {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			got <- httpResult{res.StatusCode, b, res.Header}
			return
		}
	}()

	_, msg := readMsg(t, ex)
	if len(msg) != ExchangeIDBytes+len(body) || !bytes.Equal(msg[ExchangeIDBytes:], body) {
		t.Fatalf("box saw %d bytes", len(msg))
	}
	out := append(append([]byte{}, msg[:ExchangeIDBytes]...), reply...)
	if err := ex.WriteMessage(websocket.BinaryMessage, out); err != nil {
		t.Fatal(err)
	}
	res := <-got
	if res.code != http.StatusOK || !bytes.Equal(res.body, reply) {
		t.Fatalf("watch got %d %q", res.code, res.body)
	}
	if res.hdr.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("a web page could read the answer")
	}
	if res.hdr.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content-type %q", res.hdr.Get("Content-Type"))
	}
}

func TestExchangeRateRefills(t *testing.T) {
	clk := &clock{t: testTime()}
	_, srv := startRelay(t, Options{Now: clk.Now})
	_ = dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	ex := dial(t, srv.URL, testEpoch, handleA, roleExchange, nil)
	go func() {
		for {
			_, msg, err := ex.ReadMessage()
			if err != nil {
				return
			}
			_ = ex.WriteMessage(websocket.BinaryMessage, append(append([]byte{}, msg[:ExchangeIDBytes]...), []byte{1}...))
		}
	}()
	body := bytes.Repeat([]byte{3}, exchangeRequestBytes)
	post := func() int {
		t.Helper()
		res, err := http.Post(srv.URL+"/x/"+fmt.Sprint(testEpoch)+"/"+handleA, "application/octet-stream", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	// The socket may not be in the room for the first try. That 501 is not
	// one of the thirty.
	var primed int
	for i := 0; i < 50 && primed != http.StatusOK; i++ {
		primed = post()
	}
	if primed != http.StatusOK {
		t.Fatalf("first exchange: %d", primed)
	}
	for i := 1; i < exchangePerMinute; i++ {
		if code := post(); code != http.StatusOK {
			t.Fatalf("exchange %d: %d", i, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("over the minute: %d", code)
	}
	// The address window and the room bucket both last a minute. A bucket
	// whose refill was computed with integer division (30/60 == 0) stays
	// empty after the window and still answers 429.
	clk.Set(testTime().Add(attemptWindow))
	if code := post(); code != http.StatusOK {
		t.Fatalf("after refill: %d", code)
	}
}

func TestExchangeRefusals(t *testing.T) {
	_, srv := startRelay(t, Options{})
	post := func(path string, n int) (int, string) {
		t.Helper()
		res, err := http.Post(srv.URL+path, "application/octet-stream", bytes.NewReader(bytes.Repeat([]byte{1}, n)))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := post("/x/"+fmt.Sprint(testEpoch)+"/"+handleA, exchangeRequestBytes); code != http.StatusNotFound {
		t.Fatalf("no box: %d", code)
	}
	_ = dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	// Dial returns at the handshake, a moment before the box is in the room.
	var code int
	for i := 0; i < 50; i++ {
		code, _ = post("/x/"+fmt.Sprint(testEpoch)+"/"+handleA, exchangeOpenBytes)
		if code != http.StatusNotFound {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if code != http.StatusNotImplemented {
		t.Fatalf("no exchange socket: %d", code)
	}
	if code, body := post("/x/"+fmt.Sprint(testEpoch+9)+"/"+handleA, exchangeRequestBytes); code != http.StatusConflict || body != fmt.Sprint(testEpoch) {
		t.Fatalf("wrong epoch: %d %q", code, body)
	}
	res, err := http.Get(srv.URL + "/x/" + fmt.Sprint(testEpoch) + "/" + handleA)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed || res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("GET %d", res.StatusCode)
	}
	if code, _ := post("/x/"+fmt.Sprint(testEpoch)+"/"+handleA, 10); code != http.StatusBadRequest {
		t.Fatalf("bad size: %d", code)
	}
}

func TestExchangeAcceptsThePreviousEpochDuringRotation(t *testing.T) {
	clk := &clock{t: testTime()}
	r, srv := startRelay(t, Options{Now: clk.Now})
	high := "ffffffffffffffffffffffffffffffff"
	_ = dial(t, srv.URL, testEpoch, high, roleBox, nil)
	ex := dial(t, srv.URL, testEpoch, high, roleExchange, nil)
	clk.Set(testTime().Add(time.Duration(EpochMs)*time.Millisecond + time.Millisecond))
	r.beat()

	body := bytes.Repeat([]byte{2}, exchangeRequestBytes)
	got := make(chan int, 1)
	go func() {
		client := &http.Client{Timeout: 2 * time.Second}
		for i := 0; i < 50; i++ {
			res, err := client.Post(srv.URL+"/x/"+fmt.Sprint(testEpoch)+"/"+high, "application/octet-stream", bytes.NewReader(body))
			if err != nil {
				got <- -1
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if (res.StatusCode == http.StatusNotImplemented || res.StatusCode == http.StatusNotFound) && i+1 < 50 {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			got <- res.StatusCode
			return
		}
	}()
	_, msg := readMsg(t, ex)
	if !bytes.Equal(msg[ExchangeIDBytes:], body) {
		t.Fatal("previous epoch was not delivered")
	}
	_ = ex.WriteMessage(websocket.BinaryMessage, append(append([]byte{}, msg[:ExchangeIDBytes]...), []byte{9}...))
	if code := <-got; code != http.StatusOK {
		t.Fatalf("previous epoch: %d", code)
	}
}

func TestBoxKeyProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	_, srv := startRelay(t, Options{BoxKeys: acceptKey{pub}})

	// No proof: the handle is enough, which is what today's clients send.
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	_ = box.Close()

	keyHdr, sigHdr, err := signBoxProof(key, testEpoch, handleB, roleBox)
	if err != nil {
		t.Fatal(err)
	}
	hdr := http.Header{"X-FTW-Box-Key": {keyHdr}, "X-FTW-Box-Sig": {sigHdr}}
	ok := dial(t, srv.URL, testEpoch, handleB, roleBox, hdr)
	_ = ok.Close()

	// A proof that does not verify is a bad join, even though a missing
	// one would have been admitted.
	bad := hdr.Clone()
	raw, _ := base64.RawURLEncoding.DecodeString(sigHdr)
	raw[0] ^= 0xff
	bad.Set("X-FTW-Box-Sig", base64.RawURLEncoding.EncodeToString(raw))
	conn := dial(t, srv.URL, testEpoch, handleA, roleBox, bad)
	expectClose(t, conn, CloseBadJoin, "box key")

	// The same proof does not admit the exchange socket: the role is signed.
	conn = dial(t, srv.URL, testEpoch, handleA, roleExchange, hdr)
	expectClose(t, conn, CloseBadJoin, "box key")

	// An unknown key is not a proof, signature or not.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k2, s2, err := signBoxProof(other, testEpoch, handleA, roleBox)
	if err != nil {
		t.Fatal(err)
	}
	conn = dial(t, srv.URL, testEpoch, handleA, roleBox, http.Header{"X-FTW-Box-Key": {k2}, "X-FTW-Box-Sig": {s2}})
	expectClose(t, conn, CloseBadJoin, "box key")

	_, strict := startRelay(t, Options{RequireBoxKey: true, BoxKeys: acceptKey{pub}})
	conn = dial(t, strict.URL, testEpoch, handleA, roleBox, nil)
	expectClose(t, conn, CloseBadJoin, "box key")
	// An app still joins with the handle. It does not hold the box's cloud key.
	app := dial(t, strict.URL, testEpoch, handleA, roleApp, nil)
	_ = app.Close()
}

type acceptKey struct{ pk []byte }

func (a acceptKey) RecognizesBoxKey(pk []byte) bool { return bytes.Equal(a.pk, pk) }

func TestLogsDoNotContainACommandOrAPushToken(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, srv := startRelay(t, Options{Log: log})
	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	app := dial(t, srv.URL, testEpoch, handleA, roleApp, nil)
	_, _ = readMsg(t, box)
	_, _ = readMsg(t, app)
	marker := "COMMAND-set_mode-watt-4242"
	if err := app.WriteMessage(websocket.BinaryMessage, []byte(marker)); err != nil {
		t.Fatal(err)
	}
	_, _ = readMsg(t, box)

	const token = "SECRET-PUSH-TOKEN"
	res, err := http.Post(srv.URL+"/deadman", "application/json", strings.NewReader(
		`{"id":"0123456789abcdef0123456789abcdef","endpoint":"https://push.example/`+token+`","ct":"aGVsbG8=","auth":"vapid `+token+`","deadline_s":600}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("deadman %d", res.StatusCode)
	}
	r.beat()
	if bytes.Contains(buf.Bytes(), []byte(marker)) || bytes.Contains(buf.Bytes(), []byte(token)) || bytes.Contains(buf.Bytes(), []byte(handleA)) {
		t.Fatalf("log retained a command, a token or a handle:\n%s", buf.String())
	}
}

func TestClientIPIgnoresAHeaderTheClientWrote(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.7:4242"
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 198.51.100.7")
	if got := clientIP(req, false); got != "198.51.100.7" {
		t.Fatalf("untrusted: %q", got)
	}
	if got := clientIP(req, true); got != "198.51.100.7" {
		t.Fatalf("trusted tail: %q", got)
	}
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := clientIP(req, true); got != "9.9.9.9" {
		t.Fatalf("trusted: %q", got)
	}
}

func TestCommandPathDoesNotImportAReader(t *testing.T) {
	// Standard-library deps include the TLS and RNG ciphers. Those are not a
	// reader of a command. What must stay out is this module's store and
	// any Noise or NaCl package the relay could open a frame with.
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "github.com/srcfl/ftw-cloud/internal/relay").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range strings.Split(string(out), "\n") {
		switch {
		case strings.Contains(p, "internal/store"),
			strings.Contains(p, "internal/uplink"),
			strings.Contains(p, "internal/appsession"),
			strings.Contains(p, "appwire"),
			strings.Contains(p, "cloudwire"),
			strings.Contains(p, "chacha"),
			strings.Contains(p, "nacl"),
			strings.Contains(p, "noise"):
			t.Fatalf("the command path can read what it carries: %s", p)
		}
	}
}

func TestRotationOffsetStaysInsideTheWindow(t *testing.T) {
	seen := map[time.Duration]struct{}{}
	for i := 0; i < 200; i++ {
		h := fmt.Sprintf("%04x", i*300%0x10000) + "0000000000000000000000000000"
		off := RotationOffset(h, rotateSpread)
		if off < 0 || off >= rotateSpread {
			t.Fatalf("offset %s", off)
		}
		seen[off] = struct{}{}
	}
	if len(seen) < 50 {
		t.Fatalf("only %d distinct turns", len(seen))
	}
}
