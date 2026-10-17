package webpush

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type post func(*http.Request) (*http.Response, error)

func (p post) RoundTrip(r *http.Request) (*http.Response, error) { return p(r) }
func auth(endpoint string, now time.Time) string {
	raw, _ := json.Marshal(map[string]any{"aud": endpoint, "exp": now.Add(time.Hour).Unix()})
	return "vapid t=e30." + base64.RawURLEncoding.EncodeToString(raw) + ".signature, k=public"
}

func TestOfflineNoticesKeepCiphertextAndRespectEveryGrantWithoutACopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	reg, err := registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { reg.Close() }()
	now := time.Unix(1_791_820_800, 0)
	const home = "home"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err = reg.Claim(home, elliptic.Marshal(key.Curve, key.X, key.Y), now); err != nil {
		t.Fatal(err)
	}
	svc, err := New(reg)
	if err != nil {
		t.Fatal(err)
	}
	svc.now = func() time.Time { return now }
	row := cloudwire.WebPushRow{ID: "subscription", Device: "browser", Epoch: 1, Endpoint: "https://push.example/opaque", CT: []byte("box encrypted bytes"), Auth: auth("https://push.example", now)}
	device := cloudwire.Device{ID: "browser", Key: make([]byte, 32), Epoch: 1, Role: "owner", Scopes: []string{protocol.ScopeEventsRead}}
	roster := cloudwire.Roster{RosterSeq: 1, TTLS: 86400, Devices: []cloudwire.Device{device}, WebPush: []cloudwire.WebPushRow{row}}
	save := func() {
		t.Helper()
		env, err := cloudwire.Seal(key, home, cloudwire.MsgRoster, roster)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := env.Encode()
		if err = reg.SetRoster(home, roster.RosterSeq, nil, raw, now); err != nil {
			t.Fatal(err)
		}
	}
	save()
	status := 201
	posts := 0
	svc.client = &http.Client{Transport: post(func(r *http.Request) (*http.Response, error) {
		posts++
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, row.CT) || r.Header.Get("Authorization") != row.Auth || r.Header.Get("Content-Encoding") != "aes128gcm" {
			t.Error("notice changed")
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(nil)), Header: make(http.Header)}, nil
	})}
	send := func(want int, retry bool) {
		t.Helper()
		n, again := svc.Send(context.Background(), home)
		if n != want || again != retry {
			t.Fatalf("sent %d retry %v, want %d %v", n, again, want, retry)
		}
	}
	send(0, false) // online
	due := now.Add(time.Minute)
	reg.AwaySet(home, due)
	send(0, false) // grace
	now = due
	status = 503
	send(0, true)
	status = 201
	send(1, false)
	send(0, false)
	if posts != 2 {
		t.Fatal(posts)
	}
	// The sent marker survives a process restart.
	reg.Close()
	reg, err = registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	svc.reg = reg
	send(0, false)
	reg.AwayClear(home)
	now = now.Add(time.Hour)
	reg.AwaySet(home, now)
	// Renew the box's VAPID token, then test epoch, scopes and suspension.
	row.Auth = auth("https://push.example", now)
	roster.WebPush = []cloudwire.WebPushRow{row}
	roster.Devices[0].Epoch = 2
	save()
	send(0, false)
	roster.Devices[0].Epoch = 1
	roster.Devices[0].Scopes = nil
	save()
	send(0, false)
	roster.Devices[0].Scopes = []string{protocol.ScopeEventsRead}
	save()
	reg.Suspend(home, "browser", 1, now)
	send(0, false)
	reg.Unsuspend(home, "browser")
	send(1, false)
	reg.AwayClear(home)
	send(0, false)
	now = now.Add(time.Hour)
	reg.AwaySet(home, now)
	roster.WebPush = nil
	save()
	send(0, false)
}

func TestAURLOrDNSCannotReachPrivateServices(t *testing.T) {
	now := time.Now()
	row := cloudwire.WebPushRow{Endpoint: "https://push.example/x", Auth: auth("https://push.example", now)}
	if deliveryURL(row, now.Add(2*time.Hour)) {
		t.Fatal("expired authorization accepted")
	}
	if !deliveryURL(row, now) {
		t.Fatal("valid endpoint refused")
	}
	for _, u := range []string{"http://push.example/x", "https://user@push.example/x", "https://push.example:444/x", "https://127.0.0.1/x", "https://169.254.169.254/latest/", "https://[::ffff:127.0.0.1]/", "https://push.example/x#part"} {
		row.Endpoint = u
		if deliveryURL(row, now) {
			t.Fatal(u)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.1.1.1", "169.254.169.254", "::1", "::ffff:192.168.1.2", "100.100.100.1", "fd00::1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatal(ip)
		}
	}
	if _, err := publicDial(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("local dial succeeded")
	}
}
