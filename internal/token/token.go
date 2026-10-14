// Package token gives each roster device one extension token and serves
// GET /v1/now with it. docs/protocol-cloud.md in srcfl/ftw, "Extension
// token", is the wire format.
//
// A token is 32 random bytes, base64url without padding. The registry keeps
// its SHA-256 and the roster entry it is bound to, never the token. A read
// reaches the home only through store.For with that roster entry, so a token
// stops working the moment the roster drops the device, moves its epoch or
// runs out, an owner suspends the device, or the grant ends. It reads the
// newest live, prices and hb, as the box signed them, and nothing else. It
// is not a device key and cannot command.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

const (
	// Life is how long a token reads. The app asks for a new one at each
	// foreground and background refresh.
	Life = 7 * 24 * time.Hour
	// tokenBytes is the token's length before base64url.
	tokenBytes = 32
)

// Now is the body of GET /v1/now: the box's envelopes as it signed them, in
// rising seq, and when the service last heard from the box. lastSeenMs is
// the service's own word and is never shown as a reading.
type Now struct {
	Envelopes  []cbor.RawMessage `cbor:"envelopes"`
	LastSeenMs int64             `cbor:"lastSeenMs"`
}

// Service issues tokens and answers /v1/now.
type Service struct {
	store *store.Store
	reg   *registry.Registry
	log   *slog.Logger
	now   func() time.Time
}

// New builds the service.
func New(st *store.Store, reg *registry.Registry, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, reg: reg, log: log, now: time.Now}
}

// Issue makes a new token for a roster entry, in place of the device's old
// one. dev comes from store.For, never from the device's message.
func (s *Service) Issue(home string, dev cloudwire.Device) (cloudwire.Token, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return cloudwire.Token{}, err
	}
	hash := sha256.Sum256(raw)
	row := registry.TokenRow{Home: home, DeviceID: dev.ID, Epoch: dev.Epoch, Expires: s.now().Add(Life)}
	if err := s.reg.TokenIssue(row, hash[:]); err != nil {
		return cloudwire.Token{}, err
	}
	return cloudwire.Token{Token: base64.RawURLEncoding.EncodeToString(raw), ExpiresInS: int64(Life / time.Second)}, nil
}

// Drop forgets a device's token, as when an owner suspends it.
func (s *Service) Drop(home, deviceID string) error {
	return s.reg.TokenDrop(home, deviceID)
}

// Roster drops the tokens of devices the box's roster no longer lists at
// their epoch. It runs on the box's goroutine and never blocks for long.
func (s *Service) Roster(home string, r *cloudwire.Roster) {
	if r == nil {
		return
	}
	epochs := make(map[string]uint64, len(r.Devices))
	for _, d := range r.Devices {
		epochs[d.ID] = d.Epoch
	}
	if err := s.reg.TokenPrune(home, func(id string, epoch uint64) bool {
		e, ok := epochs[id]
		return ok && e == epoch
	}); err != nil {
		s.log.Warn("could not drop the tokens a roster dropped", "err", err)
	}
}

// ServeHTTP is GET /v1/now. Every refusal is 401 with an empty body and says
// nothing about which check failed.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 {
		http.Error(w, "TLS 1.3 only", http.StatusUpgradeRequired)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := s.read(r.Header.Get("Authorization"))
	switch {
	case errors.Is(err, store.ErrDenied):
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(http.StatusUnauthorized)
		return
	case err != nil:
		s.log.Warn("a token read failed", "err", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/cbor")
	_, _ = w.Write(body)
}

// read checks a bearer token and returns the body it may read.
func (s *Service) read(auth string) ([]byte, error) {
	scheme, value, ok := strings.Cut(auth, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return nil, store.ErrDenied
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(raw) != tokenBytes {
		return nil, store.ErrDenied
	}
	hash := sha256.Sum256(raw)
	row, ok, err := s.reg.TokenLookup(hash[:], s.now())
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, store.ErrDenied
	}
	x, err := s.store.For(store.Principal{Kind: store.Token, Home: row.Home, DeviceID: row.DeviceID, Epoch: row.Epoch})
	if err != nil {
		return nil, store.ErrDenied
	}
	snap, err := x.Now()
	if err != nil {
		return nil, store.ErrDenied
	}
	out := Now{Envelopes: make([]cbor.RawMessage, len(snap.Envelopes)), LastSeenMs: snap.LastSeenMs}
	for i, e := range snap.Envelopes {
		out.Envelopes[i] = e
	}
	return cloudwire.Marshal(out)
}
