package keys

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol/appwire"
)

// Limits.
const (
	// MaxPending bounds the keys made for consents the owner has not
	// approved yet. Each authorize request makes one, so this bounds what a
	// stranger can make the keys part hold.
	MaxPending = 10_000
	// PendingFor is how long an unapproved key is kept. A consent page
	// lasts far less.
	PendingFor = time.Hour
	// MaxSessions bounds the open sessions, and IdleFor how long one lasts
	// unused. ftwcloudd closes its warm sessions sooner; these catch one it
	// lost track of.
	MaxSessions = 4096
	IdleFor     = 10 * time.Minute
	// unwrapTimeout bounds one KMS call.
	unwrapTimeout = 5 * time.Second
)

// SessionPrologue is the box session's prologue, as the box spells it
// (appuplink.prologue in srcfl/ftw). The keys part sets it itself, so it
// opens sessions for this protocol and no other.
func SessionPrologue(boxStatic []byte) []byte {
	return append([]byte("ftw.session.v1:"), boxStatic...)
}

// Server is ftwkeysd: the sealed keys on disk and the open sessions in
// memory.
type Server struct {
	dir    string
	sealer Sealer
	log    *slog.Logger
	now    func() time.Time
	// PeerUID is the one user allowed to connect, checked on each accepted
	// unix connection. Negative allows the server's own user only.
	PeerUID int

	mu       sync.Mutex
	sessions map[string]*session
}

type session struct {
	kid  string
	mu   sync.Mutex
	init *appwire.InitiatorState
	tr   *appwire.Transport
	used time.Time
}

// NewServer keeps sealed keys under dir: pending/ until the owner approves,
// then kept/.
func NewServer(dir string, sealer Sealer, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	for _, d := range []string{"pending", "kept"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	return &Server{dir: dir, sealer: sealer, log: log, now: time.Now, PeerUID: -1, sessions: map[string]*session{}}, nil
}

// Serve accepts connections until ln closes. Each must come from PeerUID.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if uc, ok := conn.(*net.UnixConn); ok {
			if err := checkPeer(uc, s.PeerUID); err != nil {
				s.log.Warn("refused a connection from another user")
				_ = conn.Close()
				continue
			}
		}
		go s.serveConn(conn)
	}
}

// Local is a client wired to this server in memory, for tests and for a
// development build that runs both parts in one process.
func (s *Server) Local() *Client {
	a, b := net.Pipe()
	go s.serveConn(b)
	return newClient(func() (net.Conn, error) { return a, nil })
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	var wmu sync.Mutex
	for {
		var req request
		if err := readFrame(conn, &req); err != nil {
			return
		}
		go func() {
			resp := s.handle(req)
			resp.ID = req.ID
			wmu.Lock()
			defer wmu.Unlock()
			_ = writeFrame(conn, resp)
		}()
	}
}

func (s *Server) handle(req request) response {
	var (
		resp response
		err  error
	)
	switch req.Op {
	case opNew:
		resp.Kid, resp.Pub, err = s.newKey()
	case opKeep:
		err = s.keep(req.Kid)
	case opForget:
		err = s.forget(req.Kid)
	case opOpen:
		resp.Sess, resp.D, err = s.open(req.Kid, req.RS)
	case opFinish:
		resp.D, err = s.finish(req.Sess, req.D)
	case opSeal:
		err = s.with(req.Sess, func(x *session) error {
			if x.tr == nil {
				return ErrRefused
			}
			resp.D, err = x.tr.Encrypt(req.D)
			return err
		})
	case opUnseal:
		err = s.with(req.Sess, func(x *session) error {
			if x.tr == nil {
				return ErrRefused
			}
			resp.D, err = x.tr.Decrypt(req.D)
			return err
		})
	case opClose:
		s.end(req.Sess)
	default:
		err = ErrRefused
	}
	if err != nil {
		return response{Err: errorText(err)}
	}
	return resp
}

// --------------------------------------------------------------------------
// Keys at rest
// --------------------------------------------------------------------------

// record is one sealed key on disk.
type record struct {
	V   int    `cbor:"v"`
	Kid string `cbor:"kid"`
	Pub []byte `cbor:"pub"`
	// DEK is the data key, wrapped by the sealer; CT the X25519 secret
	// sealed with it.
	DEK []byte `cbor:"dek"`
	CT  []byte `cbor:"ct"`
	At  int64  `cbor:"at"`
}

func keyAAD(kid string, pub []byte) []byte {
	return append([]byte("ftw.agent-key.v1\x00"+kid+"\x00"), pub...)
}

// validKid is the shape newKey makes: 16 random bytes in base64url. Nothing
// else is a file name here.
func validKid(kid string) bool {
	b, err := base64.RawURLEncoding.DecodeString(kid)
	return err == nil && len(b) == 16 && base64.RawURLEncoding.EncodeToString(b) == kid
}

func (s *Server) newKey() (string, []byte, error) {
	if n, _ := countDir(filepath.Join(s.dir, "pending")); n >= MaxPending {
		return "", nil, ErrBusy
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", nil, err
	}
	kid := base64.RawURLEncoding.EncodeToString(id)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, err
	}
	pub := priv.PublicKey().Bytes()
	secret := priv.Bytes()
	defer wipe(secret)

	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, wrapped, err := s.sealer.DataKey(ctx, kid)
	if err != nil {
		s.log.Warn("could not make a data key", "err", err)
		return "", nil, err
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return "", nil, err
	}
	ct, err := seal(aead, secret, keyAAD(kid, pub))
	if err != nil {
		return "", nil, err
	}
	raw, err := encMode.Marshal(record{V: 1, Kid: kid, Pub: pub, DEK: wrapped, CT: ct, At: s.now().UnixMilli()})
	if err != nil {
		return "", nil, err
	}
	if err := writeFile(filepath.Join(s.dir, "pending", kid), raw); err != nil {
		return "", nil, err
	}
	return kid, pub, nil
}

func (s *Server) keep(kid string) error {
	if !validKid(kid) {
		return ErrUnknownKey
	}
	from, to := filepath.Join(s.dir, "pending", kid), filepath.Join(s.dir, "kept", kid)
	if err := os.Rename(from, to); err != nil {
		if _, statErr := os.Stat(to); statErr == nil {
			return nil // kept already
		}
		return ErrUnknownKey
	}
	return syncDir(filepath.Join(s.dir, "kept"))
}

func (s *Server) forget(kid string) error {
	if !validKid(kid) {
		return ErrUnknownKey
	}
	for _, d := range []string{"pending", "kept"} {
		if err := os.Remove(filepath.Join(s.dir, d, kid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	s.mu.Lock()
	var ending []*session
	for id, x := range s.sessions {
		if x.kid == kid {
			ending = append(ending, x)
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
	for _, x := range ending {
		x.close()
	}
	return nil
}

// unseal reads a kept key. A key whose approval is still pending opens no
// session.
func (s *Server) unseal(kid string) ([]byte, error) {
	if !validKid(kid) {
		return nil, ErrUnknownKey
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, "kept", kid))
	if err != nil {
		return nil, ErrUnknownKey
	}
	var rec record
	if err := decMode.Unmarshal(raw, &rec); err != nil || rec.Kid != kid || len(rec.Pub) != appwire.DHBytes {
		return nil, ErrUnknownKey
	}
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, err := s.sealer.Unwrap(ctx, kid, rec.DEK)
	if err != nil {
		s.log.Warn("could not unwrap a data key", "err", err)
		return nil, err
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	secret, err := open(aead, rec.CT, keyAAD(kid, rec.Pub))
	if err != nil {
		return nil, ErrUnknownKey
	}
	return secret, nil
}

// --------------------------------------------------------------------------
// Sessions
// --------------------------------------------------------------------------

// open unseals kid and starts a session to the box whose static key is rs.
// The secret is wiped once message 1 is written; the handshake state keeps
// what it needs to read message 2.
func (s *Server) open(kid string, rs []byte) (string, []byte, error) {
	if len(rs) != appwire.DHBytes {
		return "", nil, ErrRefused
	}
	s.mu.Lock()
	full := len(s.sessions) >= MaxSessions
	s.mu.Unlock()
	if full {
		return "", nil, ErrBusy
	}
	secret, err := s.unseal(kid)
	if err != nil {
		return "", nil, err
	}
	kp, err := appwire.KeyPairFromSecret(secret)
	wipe(secret)
	if err != nil {
		return "", nil, err
	}
	init, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: kp, RemoteStatic: rs, Prologue: SessionPrologue(rs)})
	if err != nil {
		return "", nil, err
	}
	// A paired device's message 1 carries no payload: the box knows it by
	// its static key.
	msg1, err := init.WriteMessage(nil)
	if err != nil {
		return "", nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", nil, err
	}
	sess := base64.RawURLEncoding.EncodeToString(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= MaxSessions {
		return "", nil, ErrBusy
	}
	s.sessions[sess] = &session{kid: kid, init: init, used: s.now()}
	return sess, msg1, nil
}

func (s *Server) finish(sess string, msg2 []byte) ([]byte, error) {
	var payload []byte
	err := s.with(sess, func(x *session) error {
		if x.init == nil {
			return ErrRefused
		}
		p, err := x.init.ReadMessage(msg2)
		if err != nil {
			return ErrRefused
		}
		split, err := x.init.Split()
		if err != nil {
			return err
		}
		x.init, x.tr, payload = nil, appwire.NewTransport(split), p
		return nil
	})
	if errors.Is(err, ErrRefused) {
		// A message 2 that does not read ends the attempt: the handshake
		// state cannot take another.
		s.end(sess)
	}
	return payload, err
}

// with runs fn on one session under its own lock.
func (s *Server) with(sess string, fn func(*session) error) error {
	s.mu.Lock()
	x := s.sessions[sess]
	s.mu.Unlock()
	if x == nil {
		return ErrUnknownSession
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.used = s.now()
	return fn(x)
}

func (s *Server) end(sess string) {
	s.mu.Lock()
	x := s.sessions[sess]
	delete(s.sessions, sess)
	s.mu.Unlock()
	if x != nil {
		x.close()
	}
}

func (x *session) close() {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.tr != nil {
		x.tr.Close()
	}
	x.init, x.tr = nil, nil
}

// Sweep closes idle sessions and deletes keys whose approval never came. Run
// it every minute or so.
func (s *Server) Sweep() {
	now := s.now()
	s.mu.Lock()
	var idle []*session
	for id, x := range s.sessions {
		if x.mu.TryLock() {
			stale := now.Sub(x.used) > IdleFor
			x.mu.Unlock()
			if stale {
				idle = append(idle, x)
				delete(s.sessions, id)
			}
		}
	}
	s.mu.Unlock()
	for _, x := range idle {
		x.close()
	}
	dir := filepath.Join(s.dir, "pending")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && now.Sub(info.ModTime()) > PendingFor {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// Sessions is how many sessions are open, for the log.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// --------------------------------------------------------------------------
// Files
// --------------------------------------------------------------------------

// writeFile writes a new file whole or not at all.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func countDir(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") {
			n++
		}
	}
	return n, err
}
