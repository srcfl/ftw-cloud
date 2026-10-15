package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type posted struct {
	endpoint string
	body     []byte
}

func TestDeadmanFiresTheSealedBytesOnce(t *testing.T) {
	clk := &clock{t: testTime()}
	var mu sync.Mutex
	var got []posted
	r := New(Options{
		Log: discardLog(),
		Now: clk.Now,
		Post: func(_ context.Context, endpoint string, body []byte, h http.Header) (int, error) {
			if h.Get("Content-Encoding") != "aes128gcm" || h.Get("Authorization") != "vapid test" {
				t.Errorf("headers %v", h)
			}
			mu.Lock()
			got = append(got, posted{endpoint, append([]byte(nil), body...)})
			mu.Unlock()
			return http.StatusCreated, nil
		},
	})
	ct := []byte("sealed-farewell")
	const id = "0123456789abcdef0123456789abcdef"
	r.dead.put(deadmanIn{
		ID: id, Endpoint: "https://push.example/abc",
		CT: base64.StdEncoding.EncodeToString(ct), Auth: "vapid test", DeadlineS: 60,
	})
	r.dead.claim(id)
	r.dead.release(id)

	clk.Set(testTime().Add(61 * time.Second))
	r.beat()
	waitPosts(t, &mu, &got, 1)
	if got[0].endpoint != "https://push.example/abc" || !bytes.Equal(got[0].body, ct) {
		t.Fatalf("fired %+v", got[0])
	}

	// Claimed and released again inside the half-hour floor. One outage
	// is one message.
	r.dead.claim(id)
	r.dead.release(id)
	clk.Set(testTime().Add(61*time.Second + 61*time.Second))
	r.beat()
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("fired %d times", n)
	}
}

func TestDeadmanHTTPAndARestart(t *testing.T) {
	clk := &clock{t: testTime()}
	var mu sync.Mutex
	var got []posted
	post := func(_ context.Context, endpoint string, body []byte, _ http.Header) (int, error) {
		mu.Lock()
		got = append(got, posted{endpoint, append([]byte(nil), body...)})
		mu.Unlock()
		return http.StatusCreated, nil
	}
	path := filepath.Join(t.TempDir(), "deadman.json")
	_, srv := startRelay(t, Options{Now: clk.Now, Post: post, DeadmanPath: path})
	ct := []byte("still-sealed")
	const id = "abcdef0123456789abcdef0123456789"
	raw := `{"id":"` + id + `","endpoint":"https://push.example/abc","ct":"` +
		base64.StdEncoding.EncodeToString(ct) + `","auth":"vapid test","deadline_s":60}`
	res, err := http.Post(srv.URL+"/deadman", "application/json", strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("post %d", res.StatusCode)
	}
	res, err = http.Post(srv.URL+"/deadman", "application/json", strings.NewReader(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad body %d", res.StatusCode)
	}

	box := dial(t, srv.URL, testEpoch, handleA, roleBox, nil)
	if err := box.WriteMessage(websocket.TextMessage, []byte("deadman "+id)); err != nil {
		t.Fatal(err)
	}

	// A restart forgets the claim and arms a fresh deadline, so a box that
	// is in the middle of reconnecting is not declared gone.
	r2 := New(Options{Log: discardLog(), Now: clk.Now, Post: post, DeadmanPath: path})
	r2.beat()
	time.Sleep(20 * time.Millisecond)
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("a restart fired %d times", n)
	}
	clk.Set(testTime().Add(61 * time.Second))
	r2.beat()
	waitPosts(t, &mu, &got, 1)
	if !bytes.Equal(got[0].body, ct) {
		t.Fatalf("restart fired %q", got[0].body)
	}

	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/deadman/"+id, nil)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", res.StatusCode)
	}
}

func TestPushURLsStayOnThePublicInternet(t *testing.T) {
	for _, raw := range []string{
		"http://push.example/x",
		"https://127.0.0.1/x",
		"https://10.1.2.3/x",
		"https://169.254.169.254/latest",
		"https://100.64.1.1/x",
		"https://user:pass@push.example/x",
	} {
		if err := allowPushURL(raw); err == nil {
			t.Fatalf("%s was allowed", raw)
		}
	}
	if err := allowPushURL("https://push.example/token"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"100.64.0.1", "192.168.1.1", "::1", "169.254.1.1"} {
		if publicIP(net.ParseIP(s)) {
			t.Fatalf("%s looked public", s)
		}
	}
}

func waitPosts(t *testing.T, mu *sync.Mutex, got *[]posted, n int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		have := len(*got)
		mu.Unlock()
		if have >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	have := len(*got)
	mu.Unlock()
	t.Fatalf("got %d posts, want %d", have, n)
}
