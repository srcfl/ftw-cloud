package keys

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
)

func invitePayload(t *testing.T, s *Server, kid string, pub []byte) []byte {
	t.Helper()
	o := protocol.GrantOffer{V: 1, Key: pub, Role: protocol.RoleAgent, Scopes: []string{protocol.ScopeLiveRead}, TTLS: 86400, ExpMs: s.now().UnixMilli() + 60_000}
	raw, _ := protocol.Marshal(o)
	sig, err := s.signOffer(kid, raw)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (protocol.AgentInviteClaim{Secret: bytes.Repeat([]byte{0x81}, 32), Offer: protocol.SignedOffer{O: raw, Kid: OfferKid(s.offer.Public()), Sig: sig}}).Payload()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPendingKeyOpensOnlyTypedInvitationForItsOwnOffer(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	defer c.Close()
	b := newBox(t)
	kid, pub, err := c.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := invitePayload(t, s, kid, pub)
	if _, _, err := c.OpenInvite(ctx, kid, b.static.Public(), nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("empty invitation: %v", err)
	}
	other, _, _ := c.New(ctx)
	if _, _, err := c.OpenInvite(ctx, other, b.static.Public(), payload); !errors.Is(err, ErrRefused) {
		t.Fatalf("other key's offer: %v", err)
	}
	ksess, msg1, err := c.OpenInvite(ctx, kid, b.static.Public(), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer c.End(ctx, ksess)
	responder, _ := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: b.static, Prologue: SessionPrologue(b.static.Public())})
	got, err := responder.ReadMessage(msg1)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("typed Noise payload: %v", err)
	}
	if _, _, err := c.Open(ctx, kid, b.static.Public()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("pending ordinary session: %v", err)
	}
	if err := c.Keep(ctx, kid); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.OpenInvite(ctx, kid, b.static.Public(), payload); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("kept fallback: %v", err)
	}
}

type pausedUnwrap struct {
	Sealer
	entered, release chan struct{}
	once             sync.Once
}

func (s *pausedUnwrap) Unwrap(ctx context.Context, kid string, raw []byte) ([]byte, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.Sealer.Unwrap(ctx, kid, raw)
}

func TestForgetWinsOverAnInvitationStillUnwrappingItsKey(t *testing.T) {
	s, sealer, _ := newTestServer(t)
	b := newBox(t)
	kid, pub, err := s.newKey()
	if err != nil {
		t.Fatal(err)
	}
	payload := invitePayload(t, s, kid, pub)
	paused := &pausedUnwrap{Sealer: sealer, entered: make(chan struct{}), release: make(chan struct{})}
	s.sealer = paused
	done := make(chan error, 1)
	go func() { _, _, err := s.openPayload(kid, b.static.Public(), payload, true); done <- err }()
	<-paused.entered
	if err := s.forget(kid); err != nil {
		t.Fatal(err)
	}
	close(paused.release)
	if err := <-done; !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("forgotten key opened: %v", err)
	}
	if len(s.sessions) != 0 {
		t.Fatal("forgotten key left a session")
	}
}
