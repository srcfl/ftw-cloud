package quicdoor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// testCert is a certificate for 127.0.0.1 and the pool that trusts it.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "quicdoor test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// serve runs a door for handler on a loopback UDP port and returns its
// address.
func serve(t *testing.T, handler http.Handler, cert tls.Certificate) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- New(handler, nil).Serve(ctx, pc, &tls.Config{Certificates: []tls.Certificate{cert}})
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return pc.LocalAddr().String()
}

// client is an HTTP/3 client that trusts pool and keeps each connection it
// dials.
type client struct {
	*http.Client
	mu    sync.Mutex
	conns []*quic.Conn
}

func newClient(t *testing.T, pool *x509.CertPool) *client {
	c := &client{}
	tr := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}
	tr.Dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		conn, err := quic.DialAddr(ctx, addr, tlsCfg, cfg)
		if err == nil {
			c.mu.Lock()
			c.conns = append(c.conns, conn)
			c.mu.Unlock()
		}
		return conn, err
	}
	t.Cleanup(func() { _ = tr.Close() })
	c.Client = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	return c
}

// Over HTTP/3, r.TLS is this process's own TLS 1.3 session with the client:
// its exporter is the value the client computes on its side of the same
// QUIC connection. A box binds its hello to that value, so a proxy that
// ended TLS in between would show here.
func TestTheExporterOverHTTP3IsTheClientsOwn(t *testing.T) {
	cert, pool := testCert(t)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.ProtoMajor != 3 {
			http.Error(w, "not TLS 1.3 over HTTP/3", http.StatusUpgradeRequired)
			return
		}
		ekm, err := r.TLS.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(ekm)
	}), cert)
	c := newClient(t, pool)
	resp, err := c.Get("https://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	served, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, served)
	}
	c.mu.Lock()
	cs := c.conns[0].ConnectionState().TLS
	c.mu.Unlock()
	mine, err := cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(served) != cloudwire.EKMBytes || !bytes.Equal(served, mine) {
		t.Fatalf("the service's exporter %x is not the client's %x", served, mine)
	}
	if cs.NegotiatedProtocol != ALPNH3 {
		t.Fatalf("ALPN %q", cs.NegotiatedProtocol)
	}
}

// A connection that offers no protocol the door speaks gets no handshake.
func TestAnUnknownProtocolIsRefused(t *testing.T) {
	cert, pool := testCert(t)
	addr := serve(t, http.NotFoundHandler(), cert)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{RootCAs: pool, NextProtos: []string{"ftw-not-a-protocol"}}, nil)
	if err == nil {
		_ = conn.CloseWithError(0, "")
		t.Fatal("a connection without a known ALPN was let in")
	}
}

// quic-go offers extended CONNECT on every HTTP/3 connection. The sockets
// are not served over HTTP/3, so a CONNECT never reaches the routes.
func TestExtendedConnectNeverReachesARoute(t *testing.T) {
	reached := false
	h := onlyRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodConnect, "/v1/app?home=x", nil)
	r.Proto = "websocket"
	h.ServeHTTP(w, r)
	if reached || w.Code != http.StatusNotImplemented {
		t.Fatalf("CONNECT: %d, reached %v", w.Code, reached)
	}
}

func TestAltSvcNamesThePort(t *testing.T) {
	if got := AltSvc(443); got != `h3=":443"; ma=86400` {
		t.Fatal(got)
	}
	if p, err := PortOf(":443"); err != nil || p != 443 {
		t.Fatal(p, err)
	}
	if _, err := PortOf("443"); err == nil {
		t.Fatal("a bare port was read as an address")
	}
}

// A deploy or a crash drops the process without a word to its clients. With
// the same reset key, the next process on the port answers an old
// connection's next packet with a stateless reset, so the client knows at
// once instead of waiting out its idle timeout.
func TestARestartResetsTheOldProcesssConnections(t *testing.T) {
	cert, pool := testCert(t)
	key, err := ResetKeyFile(t.TempDir() + "/quic-reset.key")
	if err != nil {
		t.Fatal(err)
	}
	start := func(addr string) (net.PacketConn, chan error) {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		d := New(http.NotFoundHandler(), nil)
		d.ResetKey = key
		done := make(chan error, 1)
		go func() { done <- d.Serve(context.Background(), pc, &tls.Config{Certificates: []tls.Certificate{cert}}) }()
		return pc, done
	}
	old, oldDone := start("127.0.0.1:0")
	addr := old.LocalAddr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, &tls.Config{RootCAs: pool, NextProtos: []string{ALPNH3}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	// The old process goes without closing anything.
	_ = old.Close()
	<-oldDone
	next, _ := start(addr)
	defer next.Close()

	str, err := conn.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = str.Write(bytes.Repeat([]byte{0}, 200))
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the old connection still stands 3 s after the restart")
	}
	var reset *quic.StatelessResetError
	if err := context.Cause(conn.Context()); !errors.As(err, &reset) {
		t.Fatalf("the connection ended with %v, not a stateless reset", err)
	}
}

func TestTheResetKeyOutlivesTheProcess(t *testing.T) {
	path := t.TempDir() + "/quic-reset.key"
	first, err := ResetKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ResetKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if *first != *again {
		t.Fatal("a second start made a new key")
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ResetKeyFile(path); err == nil {
		t.Fatal("a key of the wrong length was taken")
	}
}

// Past retryRate new connections a second, each must prove its address;
// the bucket refills with time.
func TestAFloodOfNewcomersMustProveItsAddress(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	n := &newcomers{now: func() time.Time { return now }}
	for i := range int(retryRate) {
		if n.retry(nil) {
			t.Fatalf("newcomer %d asked to prove its address", i)
		}
	}
	if !n.retry(nil) {
		t.Fatal("past the rate, a newcomer went in on trust")
	}
	now = now.Add(100 * time.Millisecond)
	for i := range int(retryRate / 10) {
		if n.retry(nil) {
			t.Fatalf("after a tenth of a second, newcomer %d asked to prove its address", i)
		}
	}
	if !n.retry(nil) {
		t.Fatal("the bucket refilled past a tenth of a second's worth")
	}
}

// A client asked for a Retry proves its address and gets its answer.
func TestAClientAskedForARetryStillGetsIn(t *testing.T) {
	old := retryRate
	retryRate = 0
	t.Cleanup(func() { retryRate = old })
	cert, pool := testCert(t)
	addr := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}), cert)
	resp, err := newClient(t, pool).Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
		t.Fatalf("answer %q", b)
	}
}

// SIGTERM stops the door taking connections and leaves the live sessions to
// a drain. Close then ends each with 1001, so its client dials again at
// once, rather than leaving it to its idle timeout.
func TestCloseEndsEachSessionWithGoingAway(t *testing.T) {
	cert, pool := testCert(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	d := New(nil, nil)
	in := make(chan struct{}, 1)
	d.Box = func(c *Conn, _ []byte) {
		in <- struct{}{}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- d.Serve(ctx, pc, &tls.Config{Certificates: []tls.Certificate{cert}}) }()

	dial := func(within time.Duration) (*Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), within)
		defer cancel()
		return Dial(ctx, addr, &tls.Config{RootCAs: pool}, cloudwire.ALPNBox, cloudwire.TargetBox, nil)
	}
	c, err := dial(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-in:
	case <-time.After(5 * time.Second):
		t.Fatal("the box's handler never ran")
	}

	cancel()
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if late, err := dial(500 * time.Millisecond); err == nil {
		late.Close()
		t.Fatal("the door took a connection after its context ended")
	}
	if err := c.WriteMessage(websocket.BinaryMessage, []byte(`{}`)); err != nil {
		t.Fatalf("the live session ended with the context: %v", err)
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.CloseGoingAway {
		t.Fatalf("the session ended with %v, not 1001", err)
	}
}

// A door that does not serve the sessions does not offer their ALPNs, so a
// client's handshake for one fails at once and it takes the WebSocket,
// rather than winning the race and losing the session.
func TestTheDoorOffersOnlyWhatItServes(t *testing.T) {
	cert, pool := testCert(t)
	addr := serve(t, http.NotFoundHandler(), cert)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	c, err := Dial(ctx, addr, &tls.Config{RootCAs: pool}, cloudwire.ALPNBox, cloudwire.TargetBox, nil)
	if err == nil {
		c.Close()
		t.Fatal("a door without the box's handler finished a handshake for it")
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the refused handshake took %v", took)
	}
	if !strings.Contains(err.Error(), "no_application_protocol") && !strings.Contains(err.Error(), "0x178") {
		t.Fatalf("refused with %v, not for the protocol", err)
	}
}

// A box that dials again sends its target as early data, and its hello must
// bind to the exporter of that same TLS session. The door hands the box's
// handler the exporter before the handshake ends; it is the client's.
func TestABoxsEarlyTargetGetsItsSessionsExporter(t *testing.T) {
	cert, pool := testCert(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	d := New(nil, nil)
	ekms := make(chan []byte, 2)
	d.Box = func(c *Conn, ekm []byte) {
		ekms <- ekm
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Serve(ctx, pc, &tls.Config{Certificates: []tls.Certificate{cert}}) }()
	defer d.Close()

	cache := tls.NewLRUClientSessionCache(4)
	dial := func() *Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := Dial(ctx, pc.LocalAddr().String(), &tls.Config{RootCAs: pool, ClientSessionCache: cache},
			cloudwire.ALPNBox, cloudwire.TargetBox, nil)
		if err != nil {
			t.Fatal(err)
		}
		<-c.QUIC().HandshakeComplete()
		return c
	}
	first := dial()
	<-ekms
	time.Sleep(100 * time.Millisecond) // the ticket
	_ = first.Close()

	second := dial()
	defer second.Close()
	if !second.UsedEarlyData() {
		t.Fatal("the second connection used no early data")
	}
	var got []byte
	select {
	case got = <-ekms:
	case <-time.After(3 * time.Second):
		t.Fatal("the box's handler never ran")
	}
	want, err := second.Exporter()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the door's exporter for an early target is not the client's")
	}
}

// Past maxConns the door closes a new connection with 4429.
func TestAFullDoorSaysItIsBusy(t *testing.T) {
	old := maxConns
	maxConns = 1
	t.Cleanup(func() { maxConns = old })
	cert, pool := testCert(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	d := New(nil, nil)
	d.Box = func(c *Conn, _ []byte) {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = d.Serve(ctx, pc, &tls.Config{Certificates: []tls.Certificate{cert}}) }()
	defer d.Close()
	dial := func() *Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := Dial(ctx, pc.LocalAddr().String(), &tls.Config{RootCAs: pool}, cloudwire.ALPNBox, cloudwire.TargetBox, nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := dial()
	defer first.Close()
	time.Sleep(100 * time.Millisecond)
	// The close may reach the client while it dials or once it reads.
	dctx, dcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dcancel()
	second, err := Dial(dctx, pc.LocalAddr().String(), &tls.Config{RootCAs: pool}, cloudwire.ALPNBox, cloudwire.TargetBox, nil)
	if err == nil {
		defer second.Close()
		_ = second.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, err = second.ReadMessage()
	}
	var ae *quic.ApplicationError
	var ce *websocket.CloseError
	switch {
	case errors.As(err, &ae) && ae.ErrorCode == quic.ApplicationErrorCode(cloudwire.CloseBusy):
	case errors.As(err, &ce) && ce.Code == cloudwire.CloseBusy:
	default:
		t.Fatalf("the second connection ended with %v, not 4429", err)
	}
}
