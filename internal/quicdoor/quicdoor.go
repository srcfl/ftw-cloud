// Package quicdoor is FTW Cloud's door over QUIC: UDP on the same port as
// the TCP listener, with the same certificate. Each connection goes to the
// protocol its TLS handshake negotiated by ALPN. Today that is HTTP/3, for
// the routes that are plain HTTPS: /v1/app/once, /v1/now, /healthz and
// /source. The sockets, /v1/box and /v1/app, stay on TCP.
//
// TLS still ends in ftwcloudd, so r.TLS over HTTP/3 is this process's own
// TLS 1.3 session, and its exporter is the one a client on this connection
// computes.
package quicdoor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ALPNH3 is HTTP/3.
const ALPNH3 = http3.NextProtoH3

// AltSvcMaxAge is how long a client may remember that HTTP/3 is here. A day,
// so a host that loses UDP costs a client at most a day of racing for it.
const AltSvcMaxAge = 24 * time.Hour

const (
	// idleTimeout closes a quiet connection. A watch posts once per glance
	// and a widget reads once per refresh, so nothing here stays open long.
	idleTimeout = 30 * time.Second
	// handshakeTimeout bounds the TLS handshake. A client that takes longer
	// is better served by the WebSocket it races against.
	handshakeTimeout = 5 * time.Second
	// maxStreams bounds concurrent requests on one connection.
	maxStreams = 32
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

// Door accepts QUIC connections and serves HTTP/3 on them.
type Door struct {
	h3  *http3.Server
	log *slog.Logger
	// ResetKey makes stateless resets (RFC 9000, 10.3). After a restart, a
	// client of the old process gets a reset for its next packet instead
	// of silence until its idle timeout. Keep it across restarts; nil sends
	// none. Set before Serve.
	ResetKey *quic.StatelessResetKey
}

// New serves handler over HTTP/3. A nil log writes nothing.
func New(handler http.Handler, log *slog.Logger) *Door {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Door{log: log, h3: &http3.Server{
		Handler:     onlyRequests(handler),
		IdleTimeout: idleTimeout,
		// quic-go's own log names the peer's address, and an address beside
		// a time is what links a household to its traffic.
		Logger: nil,
	}}
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
func TLSConfig(base *tls.Config) *tls.Config {
	c := base.Clone()
	c.MinVersion = tls.VersionTLS13
	c.NextProtos = []string{ALPNH3}
	return c
}

// Config is the QUIC configuration the door listens with. 0-RTT is off: a
// request in early data can be replayed, and no route here has said which
// of its requests survive that.
func Config() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:  handshakeTimeout,
		MaxIdleTimeout:        idleTimeout,
		MaxIncomingStreams:    maxStreams,
		MaxIncomingUniStreams: 8,
		Allow0RTT:             false,
	}
}

// Serve accepts connections on pc until ctx ends, then closes them. pc is
// the caller's, and Serve closes it on its way out.
func (d *Door) Serve(ctx context.Context, pc net.PacketConn, tlsConf *tls.Config) error {
	tr := &quic.Transport{Conn: pc, StatelessResetKey: d.ResetKey,
		VerifySourceAddress: (&newcomers{now: time.Now}).retry}
	defer tr.Close()
	ln, err := tr.Listen(TLSConfig(tlsConf), Config())
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = d.h3.Shutdown(shutdown)
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			return err
		}
		go d.serve(conn)
	}
}

func (d *Door) serve(conn *quic.Conn) {
	switch conn.ConnectionState().TLS.NegotiatedProtocol {
	case ALPNH3:
		if err := d.h3.ServeQUICConn(conn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Debug("HTTP/3 connection ended", "err", err)
		}
	default:
		_ = conn.CloseWithError(quic.ApplicationErrorCode(http3.ErrCodeVersionFallback), "")
	}
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
