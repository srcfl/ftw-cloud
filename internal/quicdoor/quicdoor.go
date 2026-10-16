// Package quicdoor is FTW Cloud's door over QUIC: UDP on the same port as
// the TCP listener, with the same certificate. Each connection goes to the
// protocol its TLS handshake negotiated by ALPN:
//
//	h3               HTTP/3, for the plain HTTPS routes: /v1/app/once,
//	                 /v1/now, /healthz and /source
//	ftw-cloud-box/1  a box's uplink, served by the same handler as /v1/box
//	ftw-cloud-app/1  a phone's app session, as /v1/app
//
// The uplink and the app session keep their messages; Conn carries them on
// a control stream, a bulk stream and QUIC DATAGRAMs (docs/protocol-cloud.md
// in srcfl/ftw, "QUIC").
//
// TLS still ends in ftwcloudd, so r.TLS over HTTP/3 and Conn.Exporter are
// this process's own TLS 1.3 session, and its exporter is the one a client
// on the same connection computes.
package quicdoor

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// ALPNH3 is HTTP/3.
const ALPNH3 = http3.NextProtoH3

// AltSvcMaxAge is how long a client may remember that HTTP/3 is here. A day,
// so a host that loses UDP costs a client at most a day of racing for it.
const AltSvcMaxAge = 24 * time.Hour

const (
	// h3Idle closes a quiet HTTP/3 connection. A watch posts once per
	// glance and a widget reads once per refresh, so nothing there stays
	// open long.
	h3Idle = 30 * time.Second
	// handshakeTimeout bounds the TLS handshake, and the target after it. A
	// client that takes longer is better served by the WebSocket it races
	// against.
	handshakeTimeout = 5 * time.Second
	// maxStreams bounds concurrent requests on one HTTP/3 connection. A box
	// or a phone may open one control stream and one bulk stream; Conn
	// closes on more.
	maxStreams = 32
	// streamWindow and connWindow are the most a peer may have in flight to
	// the door, on one stream and on one connection. Boxes and phones send
	// little; the readable copy's bulk goes the other way.
	streamWindow = 256 << 10
	connWindow   = 512 << 10
)

// maxConns and maxHandshakes bound what the door holds at once: every
// connection, and those still in their handshake. Past either a new one is
// closed with 4429, busy, and its client tries the WebSocket or waits.
// Variables so a test can lower them.
var (
	maxConns      int64 = 20_000
	maxHandshakes int64 = 1_000
)

// retryRate is how many new connections a second the door takes on trust.
// Past it, each must prove its address with a Retry first (RFC 9000
// §8.1.2): a round trip more for a real client, and no state for a flood
// of spoofed Initials. Boxes coming back after a restart arrive spread out
// below it. A variable so a test can lower it.
var retryRate = 200.0

// newcomers is a token bucket for retryRate, with a second's worth of
// burst.
type newcomers struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	now    func() time.Time
}

// retry reports whether the next new connection must prove its address.
func (n *newcomers) retry(net.Addr) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if n.last.IsZero() {
		n.tokens = retryRate
	} else {
		n.tokens = min(retryRate, n.tokens+now.Sub(n.last).Seconds()*retryRate)
	}
	n.last = now
	if n.tokens < 1 {
		return true
	}
	n.tokens--
	return false
}

// Door accepts QUIC connections and hands each to its protocol.
type Door struct {
	h3  *http3.Server
	log *slog.Logger
	now func() time.Time
	// EarlyHeld counts phone sessions whose target came in early data and
	// waited for the handshake before the session opened.
	EarlyHeld atomic.Int64
	// conns and handshakes count what the door holds now (maxConns,
	// maxHandshakes).
	conns, handshakes atomic.Int64
	// Box serves a box's uplink over QUIC and App a phone's session, with
	// the same handlers as their WebSockets. A nil one refuses its ALPN.
	// Set before Serve.
	Box func(conn *Conn, ekm []byte)
	App func(conn *Conn, home string)
	// ResetKey makes stateless resets (RFC 9000, 10.3). After a restart, a
	// client of the old process gets a reset for its next packet instead
	// of silence until its idle timeout. Keep it across restarts; nil sends
	// none. Set before Serve.
	ResetKey *quic.StatelessResetKey

	mu     sync.Mutex
	tr     *quic.Transport
	live   map[*Conn]struct{}
	closed bool
}

// New serves handler over HTTP/3; a nil handler refuses h3. A nil log
// writes nothing.
func New(handler http.Handler, log *slog.Logger) *Door {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	d := &Door{log: log, now: time.Now}
	if handler != nil {
		d.h3 = &http3.Server{
			Handler:     onlyRequests(handler),
			IdleTimeout: h3Idle,
			// quic-go's own log names the peer's address, and an address
			// beside a time is what links a household to its traffic.
			Logger: nil,
		}
	}
	return d
}

// ResetKeyFile reads the stateless reset key at path, or writes a new one
// there the first time.
func ResetKeyFile(path string) (*quic.StatelessResetKey, error) {
	var key quic.StatelessResetKey
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) == len(key):
		copy(key[:], b)
		return &key, nil
	case err == nil:
		return nil, fmt.Errorf("%s holds %d bytes, not %d", path, len(b), len(key))
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	if _, err := rand.Read(key[:]); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key[:], 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return &key, nil
}

// AltSvc is the header value that points a client at HTTP/3 on port.
func AltSvc(port int) string {
	return fmt.Sprintf(`%s=":%d"; ma=%d`, ALPNH3, port, int(AltSvcMaxAge/time.Second))
}

// PortOf is the port of a listen address such as ":443".
func PortOf(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}

// TLSConfig is base for QUIC: TLS 1.3 and this door's protocols. It keeps
// base's certificate source, so ACME renews both listeners at once.
func TLSConfig(base *tls.Config, protos ...string) *tls.Config {
	c := base.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = protos
	return c
}

// protos are the ALPNs the door serves. One it does not serve is not
// offered, so a client's handshake for it fails at once and the client
// takes the WebSocket, rather than winning a race and losing the session.
func (d *Door) protos() []string {
	var p []string
	if d.h3 != nil {
		p = append(p, ALPNH3)
	}
	if d.Box != nil {
		p = append(p, cloudwire.ALPNBox)
	}
	if d.App != nil {
		p = append(p, cloudwire.ALPNApp)
	}
	return p
}

// Config is the QUIC configuration the door listens with. A connection
// silent for cloudwire.QUICIdleTimeout ends; boxes and phones send keepalives
// well inside it. Datagrams are on for the readable copy's hb and live.
// 0-RTT is on, under the rules in early.go.
func Config() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  handshakeTimeout,
		MaxIdleTimeout:        cloudwire.QUICIdleTimeout,
		MaxIncomingStreams:    maxStreams,
		MaxIncomingUniStreams: 8,
		EnableDatagrams:       true,
		Allow0RTT:             true,

		InitialStreamReceiveWindow:     streamWindow,
		MaxStreamReceiveWindow:         streamWindow,
		InitialConnectionReceiveWindow: connWindow,
		MaxConnectionReceiveWindow:     connWindow,
	}
}

// Serve accepts connections on pc until ctx ends. Then it takes no more,
// and the live sessions stay until Close, so a drain can end each with its
// own code. pc is the caller's.
func (d *Door) Serve(ctx context.Context, pc net.PacketConn, tlsConf *tls.Config) error {
	tr := &quic.Transport{Conn: pc, StatelessResetKey: d.ResetKey,
		VerifySourceAddress: (&newcomers{now: d.now}).retry}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.tr = tr
	d.mu.Unlock()
	tc := TLSConfig(tlsConf, d.protos()...)
	limitEarlyData(tc, d.now)
	ln, err := tr.ListenEarly(tc, Config())
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if d.h3 != nil {
			_ = d.h3.Shutdown(shutdown)
		}
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		if !d.admit(conn) {
			continue
		}
		go d.serve(conn)
	}
}

// admit counts conn against maxConns and maxHandshakes, or closes it when
// the door holds enough.
func (d *Door) admit(conn *quic.Conn) bool {
	busy := quic.ApplicationErrorCode(cloudwire.CloseBusy)
	if !done(conn) && d.handshakes.Load() >= maxHandshakes {
		// Too many handshakes at once: shed this one now. A close this
		// early loses its code (RFC 9000 §10.2.3), so its client counts QUIC
		// as failing here and takes the WebSocket.
		_ = conn.CloseWithError(busy, "")
		return false
	}
	if d.conns.Load() >= maxConns {
		// After the handshake the client reads 4429, busy, and waits.
		go func() {
			select {
			case <-conn.HandshakeComplete():
			case <-conn.Context().Done():
			}
			_ = conn.CloseWithError(busy, "")
		}()
		return false
	}
	d.conns.Add(1)
	context.AfterFunc(conn.Context(), func() { d.conns.Add(-1) })
	if !done(conn) {
		d.handshakes.Add(1)
		go func() {
			select {
			case <-conn.HandshakeComplete():
			case <-conn.Context().Done():
			}
			d.handshakes.Add(-1)
		}()
	}
	return true
}

// Close ends every live session with 1001, going away, so its client dials
// again at once, and then the transport. Call it on the way out, after
// Serve's context is done and after any drain.
func (d *Door) Close() error {
	d.mu.Lock()
	d.closed = true
	tr, live := d.tr, d.live
	d.live = nil
	d.mu.Unlock()
	var wg sync.WaitGroup
	for c := range live {
		wg.Go(func() { _ = c.Close() })
	}
	wg.Wait()
	if tr == nil {
		return nil
	}
	return tr.Close()
}

// track counts c as live until untrack, or reports false once Close has
// begun.
func (d *Door) track(c *Conn) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	if d.live == nil {
		d.live = map[*Conn]struct{}{}
	}
	d.live[c] = struct{}{}
	return true
}

func (d *Door) untrack(c *Conn) {
	d.mu.Lock()
	delete(d.live, c)
	d.mu.Unlock()
}

func (d *Door) serve(conn *quic.Conn) {
	switch alpn := conn.ConnectionState().TLS.NegotiatedProtocol; {
	case alpn == ALPNH3 && d.h3 != nil:
		// No route has said which of its requests survive a replay, so a
		// request in early data waits for the handshake.
		if !d.handshake(conn) {
			return
		}
		if err := d.h3.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Debug("HTTP/3 connection ended", "err", err)
		}
	case alpn == cloudwire.ALPNBox && d.Box != nil, alpn == cloudwire.ALPNApp && d.App != nil:
		d.session(conn, alpn == cloudwire.ALPNBox)
	default:
		_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeVersionFallback), "")
	}
}

// session reads the control stream's target and hands the connection to the
// box's or the phone's handler.
func (d *Door) session(qc *quic.Conn, box bool) {
	refuse := func(code int) { _ = qc.CloseWithError(quic.ApplicationErrorCode(code), "") }
	ctx, cancel := context.WithTimeout(qc.Context(), handshakeTimeout)
	defer cancel()
	ctrl, err := qc.AcceptStream(ctx)
	if err != nil {
		refuse(cloudwire.CloseProtocol)
		return
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(handshakeTimeout))
	r := bufio.NewReader(ctrl)
	raw, err := cloudwire.ReadMessage(r, cloudwire.MaxTarget)
	_ = ctrl.SetReadDeadline(time.Time{})
	if err != nil {
		refuse(cloudwire.CloseProtocol)
		return
	}
	target, err := url.Parse(string(raw))
	if err != nil {
		refuse(cloudwire.CloseProtocol)
		return
	}
	home := target.Query().Get(cloudwire.AppHomeParam)
	if !box && (target.Path != cloudwire.AppPath || !cloudwire.ValidHome(home)) {
		refuse(cloudwire.CloseProtocol)
		return
	}
	c := newConn(qc, ctrl, r, box)
	// A phone's message 1 may come in early data, which the network can
	// replay. Its session opens only once the handshake is done, which the
	// sender of a replay cannot do, so nothing is replaced, spent, forwarded
	// or asked for until then: for the first copy too, which matters when
	// the network dropped the original and the phone dialled again.
	if !box {
		if !done(qc) {
			d.EarlyHeld.Add(1)
		}
		if !d.handshake(qc) {
			return
		}
	}
	var ekm []byte
	if box {
		if target.Path != cloudwire.TargetBox {
			refuse(cloudwire.CloseProtocol)
			return
		}
		if ekm, err = c.Exporter(); err != nil {
			refuse(cloudwire.CloseProtocol)
			return
		}
	}
	if !d.track(c) {
		_ = c.Close()
		return
	}
	defer d.untrack(c)
	if box {
		d.Box(c, ekm)
	} else {
		d.App(c, home)
	}
	_ = c.Close()
}

// done reports whether the connection's handshake has completed.
func done(qc *quic.Conn) bool {
	select {
	case <-qc.HandshakeComplete():
		return true
	default:
		return false
	}
}

// handshake waits for the handshake, and closes a connection whose
// handshake does not finish in time.
func (d *Door) handshake(qc *quic.Conn) bool {
	t := time.NewTimer(handshakeTimeout)
	defer t.Stop()
	select {
	case <-qc.HandshakeComplete():
		return true
	case <-qc.Context().Done():
	case <-t.C:
		_ = qc.CloseWithError(quic.ApplicationErrorCode(cloudwire.CloseProtocol), "")
	}
	return false
}

// onlyRequests refuses extended CONNECT. quic-go's HTTP/3 server always
// offers it, but nothing here speaks WebSocket over HTTP/3: /v1/box and
// /v1/app are WebSockets on TCP.
func onlyRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		h.ServeHTTP(w, r)
	})
}
