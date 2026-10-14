package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testP8(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), key
}

// fakeApple is Apple's provider API, over HTTP/2 with TLS.
type fakeApple struct {
	t   *testing.T
	pub *ecdsa.PublicKey
	srv *httptest.Server

	mu      sync.Mutex
	reqs    []*http.Request
	bodies  [][]byte
	tokens  []string
	respond func(r *http.Request) (int, string)
}

func newFakeApple(t *testing.T, pub *ecdsa.PublicKey) *fakeApple {
	f := &fakeApple{t: t, pub: pub}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, r)
		f.bodies = append(f.bodies, body)
		f.tokens = append(f.tokens, strings.TrimPrefix(r.Header.Get("authorization"), "bearer "))
		respond := f.respond
		f.mu.Unlock()
		status, reason := http.StatusOK, ""
		if respond != nil {
			status, reason = respond(r)
		}
		w.Header().Set("apns-id", "00000000-0000-0000-0000-000000000000")
		w.WriteHeader(status)
		if reason != "" {
			body := map[string]any{"reason": reason}
			if status == http.StatusGone {
				body["timestamp"] = int64(1_791_820_800_000)
			}
			_ = json.NewEncoder(w).Encode(body)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeApple) client(t *testing.T, p8 []byte, now func() time.Time) *Client {
	t.Helper()
	c, err := New(Config{Key: p8, KeyID: "ABC123DEFG", TeamID: "L66M368PZ6", Topic: "energy.ftw.app",
		SandboxURL: f.srv.URL + "/sandbox", ProductionURL: f.srv.URL, HTTPClient: f.srv.Client(), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// checkToken verifies a provider token the way Apple does.
func (f *fakeApple) checkToken(token string) (header map[string]string, claims map[string]any) {
	f.t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		f.t.Fatalf("token %q", token)
	}
	dec := base64.RawURLEncoding
	h, _ := dec.DecodeString(parts[0])
	c, _ := dec.DecodeString(parts[1])
	sig, _ := dec.DecodeString(parts[2])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil || len(sig) != 64 {
		f.t.Fatalf("token %q does not parse", token)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(f.pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		f.t.Fatal("token signature does not verify")
	}
	return header, claims
}

func TestAnAlertGoesOverHTTP2WithTheSameHeadersForEveryKind(t *testing.T) {
	p8, key := testP8(t)
	apple := newFakeApple(t, &key.PublicKey)
	now := time.Unix(1_791_820_800, 0)
	c := apple.client(t, p8, func() time.Time { return now })

	payload := []byte(`{"aps":{"mutable-content":1},"ftw":{"v":1}}`)
	res, err := c.Send(context.Background(), Notification{Environment: Production,
		DeviceToken: []byte{0xab, 0xcd}, Payload: payload, Expiration: now.Add(time.Hour)})
	if err != nil || !res.OK() {
		t.Fatalf("send: %+v %v", res, err)
	}
	r := apple.reqs[0]
	if r.ProtoMajor != 2 {
		t.Fatalf("Apple was reached over HTTP/%d", r.ProtoMajor)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/3/device/abcd" {
		t.Fatalf("%s %s", r.Method, r.URL.Path)
	}
	for k, want := range map[string]string{
		"apns-topic": "energy.ftw.app", "apns-push-type": "alert", "apns-priority": "10",
		"apns-expiration": "1791824400", "content-type": "application/json",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if r.Header.Get("apns-collapse-id") != "" {
		t.Error("a collapse id says what kind an alert is")
	}
	if string(apple.bodies[0]) != string(payload) {
		t.Fatalf("payload %s", apple.bodies[0])
	}
	header, claims := apple.checkToken(apple.tokens[0])
	if header["alg"] != "ES256" || header["kid"] != "ABC123DEFG" ||
		claims["iss"] != "L66M368PZ6" || claims["iat"] != float64(now.Unix()) {
		t.Fatalf("token %v %v", header, claims)
	}
}

func TestTheProviderTokenIsRenewedEveryFortyMinutes(t *testing.T) {
	p8, key := testP8(t)
	apple := newFakeApple(t, &key.PublicKey)
	now := time.Unix(1_791_820_800, 0)
	c := apple.client(t, p8, func() time.Time { return now })
	send := func() {
		t.Helper()
		if _, err := c.Send(context.Background(), Notification{Environment: Sandbox, DeviceToken: []byte{1}, Payload: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	now = now.Add(39 * time.Minute)
	send()
	now = now.Add(2 * time.Minute)
	send()
	if apple.tokens[0] != apple.tokens[1] {
		t.Fatal("renewed inside 40 minutes")
	}
	if apple.tokens[2] == apple.tokens[1] {
		t.Fatal("still the same token after 41 minutes")
	}
	if !strings.HasPrefix(apple.reqs[0].URL.Path, "/sandbox/3/device/") {
		t.Fatalf("sandbox went to %s", apple.reqs[0].URL.Path)
	}
}

func TestAnExpiredProviderTokenIsRenewedAndTriedOnce(t *testing.T) {
	p8, key := testP8(t)
	apple := newFakeApple(t, &key.PublicKey)
	calls := 0
	apple.respond = func(*http.Request) (int, string) {
		calls++
		if calls == 1 {
			return http.StatusForbidden, "ExpiredProviderToken"
		}
		return http.StatusOK, ""
	}
	c := apple.client(t, p8, nil)
	res, err := c.Send(context.Background(), Notification{Environment: Production, DeviceToken: []byte{1}, Payload: []byte("{}")})
	if err != nil || !res.OK() || calls != 2 {
		t.Fatalf("%+v %v after %d calls", res, err, calls)
	}
}

func TestAGoneTokenSaysSo(t *testing.T) {
	p8, key := testP8(t)
	apple := newFakeApple(t, &key.PublicKey)
	for _, c := range []struct {
		status int
		reason string
		gone   bool
	}{
		{http.StatusGone, "Unregistered", true},
		{http.StatusBadRequest, "BadDeviceToken", true},
		{http.StatusBadRequest, "DeviceTokenNotForTopic", true},
		{http.StatusTooManyRequests, "TooManyRequests", false},
		{http.StatusServiceUnavailable, "ServiceUnavailable", false},
	} {
		apple.respond = func(*http.Request) (int, string) { return c.status, c.reason }
		res, err := apple.client(t, p8, nil).Send(context.Background(),
			Notification{Environment: Production, DeviceToken: []byte{1}, Payload: []byte("{}")})
		if err != nil || res.OK() || res.Gone != c.gone || res.Reason != c.reason {
			t.Fatalf("%d %s: %+v %v", c.status, c.reason, res, err)
		}
		if c.status == http.StatusGone && res.GoneSince.UnixMilli() != 1_791_820_800_000 {
			t.Fatalf("gone since %v", res.GoneSince)
		}
	}
}

func TestOnlyAnAppleKeyIsTaken(t *testing.T) {
	if _, err := New(Config{Key: []byte("not a key"), KeyID: "ABC123DEFG", TeamID: "L66M368PZ6", Topic: "x"}); err == nil {
		t.Fatal("took garbage")
	}
	p8, _ := testP8(t)
	if _, err := New(Config{Key: p8, KeyID: "short", TeamID: "L66M368PZ6", Topic: "x"}); err == nil {
		t.Fatal("took a key id Apple never issues")
	}
	c, err := New(Config{Key: p8, KeyID: "ABC123DEFG", TeamID: "L66M368PZ6", Topic: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Send(context.Background(), Notification{Environment: "staging", DeviceToken: []byte{1}}); err == nil {
		t.Fatal("sent to an environment that does not exist")
	}
}

// A widgets push goes to the app's widgets topic with Apple's own push type
// and default priority; a token from another app names that app's topic.
func TestAWidgetsPushUsesTheWidgetsTopic(t *testing.T) {
	p8, key := testP8(t)
	apple := newFakeApple(t, &key.PublicKey)
	now := time.Unix(1_791_820_800, 0)
	c := apple.client(t, p8, func() time.Time { return now })
	payload := []byte(`{"aps":{"content-changed":true}}`)
	for _, n := range []Notification{
		{Environment: Production, DeviceToken: []byte{1}, Type: PushWidgets, Payload: payload},
		{Environment: Production, DeviceToken: []byte{2}, Type: PushWidgets, App: "energy.ftw.app.watchkitapp", Payload: payload},
		{Environment: Production, DeviceToken: []byte{3}, App: "energy.ftw.app.watchkitapp", Payload: payload},
	} {
		if res, err := c.Send(context.Background(), n); err != nil || !res.OK() {
			t.Fatalf("send: %+v %v", res, err)
		}
	}
	for i, want := range []struct{ topic, kind, priority string }{
		{"energy.ftw.app.push-type.widgets", "widgets", ""},
		{"energy.ftw.app.watchkitapp.push-type.widgets", "widgets", ""},
		{"energy.ftw.app.watchkitapp", "alert", "10"},
	} {
		r := apple.reqs[i]
		if r.Header.Get("apns-topic") != want.topic || r.Header.Get("apns-push-type") != want.kind ||
			r.Header.Get("apns-priority") != want.priority {
			t.Errorf("push %d: topic %q, type %q, priority %q", i, r.Header.Get("apns-topic"),
				r.Header.Get("apns-push-type"), r.Header.Get("apns-priority"))
		}
	}
	if _, err := c.Send(context.Background(), Notification{Environment: Production, DeviceToken: []byte{4}, Type: "background"}); err == nil {
		t.Fatal("an unknown push type was sent")
	}
}
