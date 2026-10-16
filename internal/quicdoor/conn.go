package quicdoor

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go"
	"github.com/srcfl/ftw-cloud/internal/wire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Conn is one QUIC connection to a box or a phone as a wire.Conn, so the
// uplink and the app session serve it as they serve a WebSocket. Binary
// messages go on the control stream, wire.Bulk on a unidirectional stream
// each way, and wire.Datagram as QUIC DATAGRAMs. docs/protocol-cloud.md in
// srcfl/ftw, "QUIC", is the framing.
//
// QUIC's own keepalive and idle timeout stand in for the WebSocket ping: a
// ping succeeds while the connection lives, and its pong is immediate.
type Conn struct {
	qc   *quic.Conn
	ctrl *quic.Stream
	r    *bufio.Reader
	// bulkIn says whether the peer may open a bulk stream: a box may, a
	// phone sends everything on the control stream.
	bulkIn bool

	limit atomic.Int64
	start sync.Once
	in    chan inbound
	// pending holds messages the door read before handing the connection
	// over; ReadMessage returns them first.
	pending [][]byte

	mu       sync.Mutex
	deadline time.Time
	kick     chan struct{}
	pong     func(string) error
	writeDL  time.Time
	readErr  error

	writeMu sync.Mutex
	bulkMu  sync.Mutex
	bulk    *quic.SendStream
	noBulk  bool
	closed  sync.Once

	// A client's early data: what it wrote before the handshake completed,
	// sent again on a new control stream if the service rejects it. resumed
	// closes once that is done. Under writeMu.
	early     bool
	earlySent [][]byte
	resumed   chan struct{}
}

type inbound struct {
	kind int
	msg  []byte
	err  error
}

func newConn(qc *quic.Conn, ctrl *quic.Stream, r *bufio.Reader, bulkIn bool) *Conn {
	c := &Conn{qc: qc, ctrl: ctrl, r: r, bulkIn: bulkIn, in: make(chan inbound), kick: make(chan struct{}, 1)}
	c.limit.Store(cloudwire.MaxTunFrame)
	return c
}

var _ wire.Conn = (*Conn)(nil)
var _ wire.Carrier = (*Conn)(nil)

// Exporter is the TLS exporter of the session inside this connection, which
// a box binds its hello to.
func (c *Conn) Exporter() ([]byte, error) {
	cs := c.qc.ConnectionState().TLS
	return cs.ExportKeyingMaterial(cloudwire.EKMLabel, nil, cloudwire.EKMBytes)
}

// Transport is the registry's name for QUIC.
func (c *Conn) Transport() string { return cloudwire.TransportQUIC }

// Carries reports whether a message type can go now: bulk while the peer
// grants a stream for it, a datagram when both ends offered datagrams.
func (c *Conn) Carries(messageType int) bool {
	switch messageType {
	case websocket.BinaryMessage:
		return true
	case wire.Bulk:
		c.bulkMu.Lock()
		defer c.bulkMu.Unlock()
		return !c.noBulk
	case wire.Datagram:
		d := c.qc.ConnectionState().SupportsDatagrams
		return d.Local && d.Remote
	}
	return false
}

// ReadMessage returns the next message from any of the connection's paths,
// with the type it came by.
func (c *Conn) ReadMessage() (int, []byte, error) {
	if len(c.pending) > 0 {
		m := c.pending[0]
		c.pending = c.pending[1:]
		return websocket.BinaryMessage, m, nil
	}
	c.start.Do(c.readers)
	for {
		c.mu.Lock()
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, nil, err
		}
		deadline := c.deadline
		c.mu.Unlock()
		var expired <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			wait := time.Until(deadline)
			if wait <= 0 {
				return 0, nil, c.fail(errTimeout)
			}
			timer = time.NewTimer(wait)
			expired = timer.C
		}
		select {
		case m := <-c.in:
			stop(timer)
			if m.err != nil {
				return 0, nil, c.fail(m.err)
			}
			return m.kind, m.msg, nil
		case <-expired:
			return 0, nil, c.fail(errTimeout)
		case <-c.kick:
			stop(timer)
		}
	}
}

func stop(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

// fail makes err the answer to every later read, as gorilla does.
func (c *Conn) fail(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readErr == nil {
		c.readErr = err
	}
	return c.readErr
}

// readers start on the first read, once the handler has set its limit.
func (c *Conn) readers() {
	ctx := c.qc.Context()
	deliver := func(m inbound) bool {
		if m.err != nil {
			// An error is kept, not queued: the connection may already be
			// gone, and a reader waiting on it must still hear why.
			c.fail(m.err)
			select {
			case c.kick <- struct{}{}:
			default:
			}
			return false
		}
		select {
		case c.in <- m:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		for {
			msg, err := cloudwire.ReadMessage(c.reader(), int(c.limit.Load()))
			if errors.Is(err, quic.Err0RTTRejected) && c.resumed != nil {
				// The service rejected the early data; the control stream
				// starts again once the handshake is done.
				select {
				case <-c.resumed:
					continue
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				deliver(inbound{err: c.readError(err)})
				return
			}
			if !deliver(inbound{kind: websocket.BinaryMessage, msg: msg}) {
				return
			}
		}
	}()
	go func() {
		for {
			d, err := c.qc.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			if !deliver(inbound{kind: wire.Datagram, msg: d}) {
				return
			}
		}
	}()
	go func() {
		// The peer gets one bulk stream, if any; a second stream of either
		// kind breaks the protocol.
		gotBulk := false
		for {
			str, err := c.qc.AcceptUniStream(ctx)
			if err != nil {
				return
			}
			if !c.bulkIn || gotBulk {
				c.closeWith(cloudwire.CloseProtocol, "")
				return
			}
			gotBulk = true
			go func() {
				r := bufio.NewReader(str)
				for {
					msg, err := cloudwire.ReadMessage(r, int(c.limit.Load()))
					if err != nil {
						if !errors.Is(err, io.EOF) {
							deliver(inbound{err: c.readError(err)})
						}
						return
					}
					if !deliver(inbound{kind: wire.Bulk, msg: msg}) {
						return
					}
				}
			}()
		}
	}()
	go func() {
		if str, err := c.qc.AcceptStream(ctx); err == nil {
			str.CancelRead(0)
			c.closeWith(cloudwire.CloseProtocol, "")
		}
	}()
}

// readError is what a read reports: the peer's close as a WebSocket close,
// so the handlers' checks read the same over both.
func (c *Conn) readError(err error) error {
	if ae, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return &websocket.CloseError{Code: int(ae.ErrorCode), Text: ae.ErrorMessage}
	}
	if errors.Is(err, io.EOF) {
		return &websocket.CloseError{Code: websocket.CloseNormalClosure}
	}
	if errors.Is(err, cloudwire.ErrQUICMessage) {
		c.closeWith(cloudwire.CloseProtocol, "")
		return websocket.ErrReadLimit
	}
	return err
}

// WriteMessage sends one message by the path its type names. A datagram
// that does not fit, or a bulk message the peer has no stream for, goes on
// the control stream.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	switch messageType {
	case websocket.BinaryMessage:
		return c.writeStream(data)
	case wire.Datagram:
		if c.Carries(wire.Datagram) {
			err := c.qc.SendDatagram(data)
			if err == nil {
				return nil
			}
			if _, tooLarge := errors.AsType[*quic.DatagramTooLargeError](err); !tooLarge {
				return err
			}
		}
		return c.writeStream(data)
	case wire.Bulk:
		if ok, err := c.writeBulk(data); ok || err != nil {
			return err
		}
		return c.writeStream(data)
	}
	return errors.New("quicdoor: no such message type")
}

// reader is the control stream's reader, which a rejected early flight
// replaces.
func (c *Conn) reader() *bufio.Reader {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.r
}

func (c *Conn) writeStream(data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.early {
		c.earlySent = append(c.earlySent, data)
	}
	c.mu.Lock()
	dl := c.writeDL
	c.mu.Unlock()
	if err := c.ctrl.SetWriteDeadline(dl); err != nil {
		return err
	}
	_, err := c.ctrl.Write(cloudwire.AppendMessage(nil, data))
	return err
}

// writeBulk sends on the bulk stream, opening it the first time. False
// means the peer grants no stream for it.
func (c *Conn) writeBulk(data []byte) (bool, error) {
	c.bulkMu.Lock()
	defer c.bulkMu.Unlock()
	if c.noBulk {
		return false, nil
	}
	if c.bulk == nil {
		s, err := c.qc.OpenUniStream()
		if err != nil {
			c.noBulk = true
			return false, nil
		}
		c.bulk = s
	}
	c.mu.Lock()
	dl := c.writeDL
	c.mu.Unlock()
	if err := c.bulk.SetWriteDeadline(dl); err != nil {
		return true, err
	}
	_, err := c.bulk.Write(cloudwire.AppendMessage(nil, data))
	return true, err
}

// WriteControl stands in for the WebSocket's control frames. A ping
// succeeds while the connection lives, since QUIC closes one that has been
// silent for its idle timeout; a close ends the connection with the code as
// its application error.
func (c *Conn) WriteControl(messageType int, data []byte, _ time.Time) error {
	switch messageType {
	case websocket.PingMessage:
		if err := c.qc.Context().Err(); err != nil {
			return net.ErrClosed
		}
		c.mu.Lock()
		pong := c.pong
		c.mu.Unlock()
		if pong != nil {
			return pong(string(data))
		}
		return nil
	case websocket.CloseMessage:
		code, text := websocket.CloseNoStatusReceived, ""
		if len(data) >= 2 {
			code, text = int(binary.BigEndian.Uint16(data)), string(data[2:])
		}
		c.closeWith(code, text)
		return nil
	case websocket.PongMessage:
		return nil
	}
	return errors.New("quicdoor: no such control message")
}

func (c *Conn) closeWith(code int, text string) {
	c.closed.Do(func() {
		_ = c.qc.CloseWithError(quic.ApplicationErrorCode(code), text)
	})
}

// SetReadDeadline bounds the next read, as on a WebSocket.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return nil
}

// SetWriteDeadline bounds each later write.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDL = t
	c.mu.Unlock()
	return nil
}

// SetReadLimit bounds a message on either stream.
func (c *Conn) SetReadLimit(limit int64) { c.limit.Store(limit) }

// SetPongHandler runs on each ping that finds the connection alive.
func (c *Conn) SetPongHandler(h func(appData string) error) {
	c.mu.Lock()
	c.pong = h
	c.mu.Unlock()
}

// Close ends the connection. A close code sent before wins.
func (c *Conn) Close() error {
	c.closeWith(websocket.CloseGoingAway, "")
	return nil
}

// Context ends when the connection does.
func (c *Conn) Context() context.Context { return c.qc.Context() }

// errTimeout is a read past its deadline, a net.Error like the WebSocket's.
var errTimeout error = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "quicdoor: read deadline passed" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// ClientConfig is how a box or a phone dials: a keepalive well inside the
// NAT timeouts, the shared idle timeout, and datagrams on.
func ClientConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout: handshakeTimeout,
		MaxIdleTimeout:       cloudwire.QUICIdleTimeout,
		KeepAlivePeriod:      cloudwire.QUICKeepAlive,
		EnableDatagrams:      true,
	}
}

// Dial is a client's side: QUIC to addr with alpn, then the control stream
// with target first on it. Tests and measurements use it; the box's own
// dialler lives in srcfl/ftw. A nil conf is ClientConfig. With a session
// cache in tlsConf and a ticket in it, Dial returns before the handshake is
// done, and what the client writes until then goes as early data.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config, alpn, target string, conf *quic.Config) (*Conn, error) {
	tc := tlsConf.Clone()
	tc.NextProtos = []string{alpn}
	tc.MinVersion = tls.VersionTLS13
	if conf == nil {
		conf = ClientConfig()
	}
	udp, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	// Connection ids of its own, so the connection can move to another
	// path: a phone from Wi-Fi to cellular.
	tr := &quic.Transport{Conn: pc, ConnectionIDLength: 4}
	dial := tr.Dial
	if tc.ClientSessionCache != nil {
		dial = tr.DialEarly
	}
	qc, err := dial(ctx, udp, tc, conf)
	if err != nil {
		_ = tr.Close()
		return nil, err
	}
	go func() {
		<-qc.Context().Done()
		_ = tr.Close()
	}()
	return open(ctx, qc, target)
}

// open starts the control stream on a dialled connection.
func open(ctx context.Context, qc *quic.Conn, target string) (*Conn, error) {
	str, err := qc.OpenStreamSync(ctx)
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return nil, err
	}
	if _, err := str.Write(cloudwire.AppendMessage(nil, []byte(target))); err != nil {
		_ = qc.CloseWithError(0, "")
		return nil, err
	}
	c := newConn(qc, str, bufio.NewReader(str), true)
	if !done(qc) {
		c.early, c.earlySent, c.resumed = true, [][]byte{[]byte(target)}, make(chan struct{})
		go c.afterEarly()
	}
	return c, nil
}

// afterEarly waits for the handshake. If the service rejected the early
// data, it opens the control stream again and sends what went early.
func (c *Conn) afterEarly() {
	ctx := c.qc.Context()
	select {
	case <-c.qc.HandshakeComplete():
	case <-ctx.Done():
		return
	}
	defer close(c.resumed)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	sent := c.earlySent
	c.early, c.earlySent = false, nil
	if c.qc.ConnectionState().Used0RTT {
		return
	}
	next, err := c.qc.NextConnection(ctx)
	if err != nil {
		return
	}
	str, err := next.OpenStreamSync(ctx)
	if err != nil {
		c.closeWith(cloudwire.CloseProtocol, "")
		return
	}
	for _, m := range sent {
		if _, err := str.Write(cloudwire.AppendMessage(nil, m)); err != nil {
			c.closeWith(cloudwire.CloseProtocol, "")
			return
		}
	}
	c.qc, c.ctrl, c.r = next, str, bufio.NewReader(str)
}

// UsedEarlyData reports whether the handshake took the client's early
// data. Meaningful once the handshake is done.
func (c *Conn) UsedEarlyData() bool { return c.qc.ConnectionState().Used0RTT }

// QUIC is the connection underneath, for tests that move it to a new path.
func (c *Conn) QUIC() *quic.Conn { return c.qc }
