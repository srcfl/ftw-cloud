package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// onS2 is this instance as s1, with home on s2.
func onS2(t *testing.T, home string) *shard.Directory {
	t.Helper()
	d, err := shard.File{Self: "s1", Default: "s1",
		Shards: map[string]string{"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
		Homes:  map[string]string{home: "s2"}}.Directory()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (s *stack) client() *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
}

// closeOf reads until the socket closes and returns its code and reason.
func closeOf(t *testing.T, conn *websocket.Conn) (int, string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			var ce *websocket.CloseError
			if errors.As(err, &ce) {
				return ce.Code, ce.Text
			}
			t.Fatalf("no close: %v", err)
		}
	}
}

// A phone that dials an instance not holding its home hears the host that
// does before it has sent message 1, so it spends no handshake here.
func TestAPhoneOfAnotherShardIsSentThereBeforeMessage1(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	s.app.Shards = onS2(t, box.home)
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	d := websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	conn, _, err := d.Dial(strings.Replace(s.srv.URL, "https://", "wss://", 1)+"/v1/app?home="+box.home, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if code, host := closeOf(t, conn); code != cloudwire.CloseWrongShard || host != "s2.cloud.ftw.energy" {
		t.Fatalf("close %d %q", code, host)
	}
}

// A watch that posts to an instance not holding its home gets 421 and the
// host, with an empty body, before its message 1 is read.
func TestAWatchOfAnotherShardGets421(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	s.app.Shards = onS2(t, box.home)
	resp, err := s.client().Post(s.srv.URL+"/v1/app/once?home="+box.home, "application/octet-stream", bytes.NewReader([]byte{1, 2, 3}))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != cloudwire.StatusWrongShard || resp.Header.Get(cloudwire.ShardHeader) != "s2.cloud.ftw.energy" || resp.ContentLength > 0 {
		t.Fatalf("%d %q %d", resp.StatusCode, resp.Header.Get(cloudwire.ShardHeader), resp.ContentLength)
	}
}

// Before the service stops, every phone and box is told to come back within
// the spread.
func TestDrainSendsPhonesAndBoxesToComeBack(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBox()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	var phone *tunPhone
	eventually(t, "the phone is admitted", func() bool {
		phone = s.dialPhone(box.home, key, cloudwire.Now{Hz: 1}, "")
		return phone.conn != nil && phone.tr != nil
	})
	if n := s.app.Drain("1500"); n < 1 {
		t.Fatalf("drained %d phones", n)
	}
	s.up.Drain("1500")
	// The phone's reader closes tuns once it has recorded why it ended.
	for range phone.tuns {
	}
	var ce *websocket.CloseError
	if !errors.As(phone.ended, &ce) || ce.Code != cloudwire.CloseRestart || ce.Text != "1500" {
		t.Fatalf("the phone heard %v", phone.ended)
	}
	select {
	case <-box.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the box's uplink stayed open")
	}
	box.mu.Lock()
	defer box.mu.Unlock()
	if !errors.As(box.ended, &ce) || ce.Code != cloudwire.CloseRestart || ce.Text != "1500" {
		t.Fatalf("the box heard %v", box.ended)
	}
}
