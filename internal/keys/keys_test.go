package keys

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
)

func newTestServer(t *testing.T) (*Server, *FileSealer, *bytes.Buffer) {
	t.Helper()
	master := bytes.Repeat([]byte{7}, dataKeyBytes)
	sealer, err := FileSealerFromKey(master)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := NewServer(t.TempDir(), sealer, log)
	if err != nil {
		t.Fatal(err)
	}
	return s, sealer, &logs
}

// box is the responder half of one session, as the box runs it.
type box struct {
	static appwire.KeyPair
}

func newBox(t *testing.T) box {
	kp, err := appwire.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return box{static: kp}
}

func (b box) answer(t *testing.T, msg1 []byte) (msg2 []byte, tr *appwire.Transport, agent []byte) {
	t.Helper()
	hs, err := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: b.static, Prologue: SessionPrologue(b.static.Public())})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hs.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("the box cannot read message 1: %v", err)
	}
	if len(payload) != 0 {
		t.Fatalf("message 1 carries %d bytes; a paired device sends none", len(payload))
	}
	if msg2, err = hs.WriteMessage(nil); err != nil {
		t.Fatal(err)
	}
	split, err := hs.Split()
	if err != nil {
		t.Fatal(err)
	}
	return msg2, appwire.NewTransport(split), split.RemoteStatic
}

var ctx = context.Background()

// A key opens a session only once its agent is approved, and the box then
// sees the key the owner approved: the public half the keys part handed out.
func TestAKeyOpensASessionOnlyAfterApproval(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	b := newBox(t)

	kid, pub, err := c.New(ctx)
	if err != nil || len(pub) != appwire.DHBytes || !validKid(kid) {
		t.Fatalf("new: %q %d %v", kid, len(pub), err)
	}
	if _, _, err := c.Open(ctx, kid, b.static.Public()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("open before approval: %v", err)
	}
	if err := c.Keep(ctx, kid); err != nil {
		t.Fatal(err)
	}
	if err := c.Keep(ctx, kid); err != nil {
		t.Fatalf("keep is idempotent: %v", err)
	}
	sess, msg1, err := c.Open(ctx, kid, b.static.Public())
	if err != nil {
		t.Fatal(err)
	}
	msg2, boxTr, agent := b.answer(t, msg1)
	if !bytes.Equal(agent, pub) {
		t.Fatal("the box sees another key than the one approved")
	}
	if err := c.Finish(ctx, sess, msg2); err != nil {
		t.Fatal(err)
	}

	// Both ways, in order and out of it.
	for i := range 3 {
		frame := []byte{byte(i), 'a', 'g', 'e', 'n', 't'}
		msg, err := c.Seal(ctx, sess, frame)
		if err != nil {
			t.Fatal(err)
		}
		got, err := boxTr.Decrypt(msg)
		if err != nil || !bytes.Equal(got, frame) {
			t.Fatalf("box read %q, %v", got, err)
		}
		reply, _ := boxTr.Encrypt([]byte("box"))
		back, err := c.Unseal(ctx, sess, reply)
		if err != nil || string(back) != "box" {
			t.Fatalf("agent read %q, %v", back, err)
		}
	}
	// A replayed box message is refused.
	reply, _ := boxTr.Encrypt([]byte("once"))
	if _, err := c.Unseal(ctx, sess, reply); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unseal(ctx, sess, reply); err == nil {
		t.Fatal("a replay was accepted")
	}

	if err := c.End(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(ctx, sess, []byte("x")); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("seal after end: %v", err)
	}
}

// Message 1 is bound to one box: another box's key cannot read it, and the
// prologue names the box, so a session cannot be moved between them.
func TestASessionIsBoundToItsBox(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	kid, _, _ := c.New(ctx)
	_ = c.Keep(ctx, kid)
	a, other := newBox(t), newBox(t)
	_, msg1, err := c.Open(ctx, kid, a.static.Public())
	if err != nil {
		t.Fatal(err)
	}
	hs, _ := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: other.static, Prologue: SessionPrologue(other.static.Public())})
	if _, err := hs.ReadMessage(msg1); err == nil {
		t.Fatal("another box read message 1")
	}
	if _, _, err := c.Open(ctx, kid, []byte("short")); !errors.Is(err, ErrRefused) {
		t.Fatalf("open with a malformed box key: %v", err)
	}
}

// A bad message 2 ends the attempt rather than leaving a half-open session.
func TestABadMessage2EndsTheAttempt(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	kid, _, _ := c.New(ctx)
	_ = c.Keep(ctx, kid)
	b := newBox(t)
	sess, _, _ := c.Open(ctx, kid, b.static.Public())
	if err := c.Finish(ctx, sess, bytes.Repeat([]byte{1}, 48)); !errors.Is(err, ErrRefused) {
		t.Fatalf("finish with noise: %v", err)
	}
	if s.Sessions() != 0 {
		t.Fatal("the failed attempt is still held")
	}
	// Sealing before the handshake finished is refused too.
	sess, _, _ = c.Open(ctx, kid, b.static.Public())
	if _, err := c.Seal(ctx, sess, []byte("early")); !errors.Is(err, ErrRefused) {
		t.Fatalf("seal before finish: %v", err)
	}
}

// Forget deletes the key and ends its sessions at once: revoking an agent
// leaves nothing in the keys part that could act for it.
func TestForgetEndsEverySessionOfTheKey(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	kid, _, _ := c.New(ctx)
	_ = c.Keep(ctx, kid)
	b := newBox(t)
	sess, msg1, _ := c.Open(ctx, kid, b.static.Public())
	msg2, _, _ := b.answer(t, msg1)
	_ = c.Finish(ctx, sess, msg2)

	other, _, _ := c.New(ctx)
	_ = c.Keep(ctx, other)
	osess, _, _ := c.Open(ctx, other, b.static.Public())

	if err := c.Forget(ctx, kid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(ctx, sess, []byte("x")); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("seal after forget: %v", err)
	}
	if _, _, err := c.Open(ctx, kid, b.static.Public()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("open after forget: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "kept", kid)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the sealed key is still on disk")
	}
	if _, err := c.Seal(ctx, osess, []byte("x")); errors.Is(err, ErrUnknownSession) {
		t.Fatal("forgetting one key ended another key's session")
	}
}

// No key id names a file outside the state directory.
func TestKidsAreNeverPaths(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	for _, kid := range []string{"", "../kept/x", "..", "a/b", "AAAAAAAAAAAAAAAAAAAAAA==", "kept"} {
		if err := c.Keep(ctx, kid); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("keep %q: %v", kid, err)
		}
		if err := c.Forget(ctx, kid); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("forget %q: %v", kid, err)
		}
		if _, _, err := c.Open(ctx, kid, make([]byte, 32)); !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("open %q: %v", kid, err)
		}
	}
}

// The secret is on disk only sealed, a record moved to another kid does not
// open, and nothing the keys part logs or answers carries it.
func TestTheKeyIsSealedAndNeverLogged(t *testing.T) {
	s, sealer, logs := newTestServer(t)
	c := s.Local()
	b := newBox(t)
	kid, pub, _ := c.New(ctx)
	_ = c.Keep(ctx, kid)
	raw, err := os.ReadFile(filepath.Join(s.dir, "kept", kid))
	if err != nil {
		t.Fatal(err)
	}
	var rec record
	if err := decMode.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	dek, err := sealer.Unwrap(ctx, kid, rec.DEK)
	if err != nil {
		t.Fatal(err)
	}
	aead, _ := newGCM(dek)
	secret, err := open(aead, rec.CT, keyAAD(kid, pub))
	if err != nil || len(secret) != 32 {
		t.Fatalf("the test cannot unseal its own key: %v", err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("the secret is on disk in the clear")
	}

	// The same record under another kid does not open: the kid is bound
	// into both the data key and the sealed secret.
	other, _, _ := c.New(ctx)
	_ = c.Keep(ctx, other)
	if err := os.WriteFile(filepath.Join(s.dir, "kept", other), bytes.ReplaceAll(raw, []byte(kid), []byte(other)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Open(ctx, other, b.static.Public()); err == nil {
		t.Fatal("a sealed key opened under another kid")
	}

	// Run every operation, then look for the secret in what was said.
	sess, msg1, _ := c.Open(ctx, kid, b.static.Public())
	msg2, _, _ := b.answer(t, msg1)
	_ = c.Finish(ctx, sess, msg2)
	_, _ = c.Seal(ctx, sess, []byte("frame"))
	_, _ = c.Unseal(ctx, sess, []byte("not a message at all, at least 24 bytes"))
	_ = c.Forget(ctx, kid)
	for _, form := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(base64.StdEncoding.EncodeToString(secret)),
		[]byte(base64.RawURLEncoding.EncodeToString(secret)), dek, []byte(hex.EncodeToString(dek))} {
		if bytes.Contains(logs.Bytes(), form) {
			t.Fatal("the log carries key material")
		}
	}
}

// An error crossing the socket is one of a few fixed words.
func TestErrorsSayNothingAboutKeys(t *testing.T) {
	failing := errors.New("kms said: key material 0123456789abcdef")
	if got := errorText(failing); got != "failed" {
		t.Fatalf("errorText = %q", got)
	}
	if got := errorText(errors.Join(ErrBusy, failing)); got != ErrBusy.Error() {
		t.Fatalf("errorText = %q", got)
	}
}

// fakeKMS checks the encryption context the way KMS does: a blob opens only
// under the context it was made with.
type fakeKMS struct {
	mu    sync.Mutex
	blobs map[string]struct {
		plain []byte
		ctx   map[string]string
		key   string
	}
	calls int
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, keyID string, c map[string]string) ([]byte, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	plain := bytes.Repeat([]byte{byte(f.calls)}, 32)
	blob := []byte("blob-" + string(rune('a'+f.calls)))
	if f.blobs == nil {
		f.blobs = map[string]struct {
			plain []byte
			ctx   map[string]string
			key   string
		}{}
	}
	f.blobs[string(blob)] = struct {
		plain []byte
		ctx   map[string]string
		key   string
	}{bytes.Clone(plain), maps.Clone(c), keyID}
	return plain, blob, nil
}

func (f *fakeKMS) Decrypt(_ context.Context, keyID string, blob []byte, c map[string]string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	b, ok := f.blobs[string(blob)]
	if !ok || b.key != keyID || !maps.Equal(b.ctx, c) {
		return nil, errors.New("InvalidCiphertextException")
	}
	return bytes.Clone(b.plain), nil
}

// With KMS, each key has its own data key, wrapped under a context that
// names the purpose and the kid; the key policy can require the purpose.
func TestKMSSealerBindsTheContext(t *testing.T) {
	kms := &fakeKMS{}
	sealer := KMSSealer{KMS: kms, KeyID: "alias/ftw-cloud-agent-keys"}
	s, err := NewServer(t.TempDir(), sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Local()
	b := newBox(t)
	kid, _, err := c.New(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Keep(ctx, kid)
	var wrapped []byte
	for b, blob := range kms.blobs {
		if blob.ctx["purpose"] != EncryptionContextPurpose || (blob.ctx["kid"] != kid && blob.ctx["kid"] != offerKid) {
			t.Fatalf("encryption context %v", blob.ctx)
		}
		if blob.ctx["kid"] == kid {
			wrapped = []byte(b)
		}
	}
	if wrapped == nil {
		t.Fatal("no data key for the agent key")
	}
	before := kms.calls
	sess, msg1, err := c.Open(ctx, kid, b.static.Public())
	if err != nil || sess == "" {
		t.Fatalf("open through KMS: %v", err)
	}
	if kms.calls != before+1 {
		t.Fatalf("opening a session made %d KMS calls, want 1", kms.calls-before)
	}
	_, _, _ = b.answer(t, msg1)

	// The wrapped data key does not open for another kid.
	if _, err := sealer.Unwrap(ctx, "AAAAAAAAAAAAAAAAAAAAAA", wrapped); err == nil {
		t.Fatal("a data key opened under another kid")
	}
}

// Keys whose approval never came go after PendingFor, and idle sessions
// after IdleFor.
func TestSweepDropsStalePendingKeysAndIdleSessions(t *testing.T) {
	s, _, _ := newTestServer(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	c := s.Local()
	stale, _, _ := c.New(ctx)
	fresh, _, _ := c.New(ctx)
	kept, _, _ := c.New(ctx)
	_ = c.Keep(ctx, kept)
	old := now.Add(-PendingFor - time.Minute)
	_ = os.Chtimes(filepath.Join(s.dir, "pending", stale), old, old)
	_ = os.Chtimes(filepath.Join(s.dir, "kept", kept), old, old)
	b := newBox(t)
	sess, _, _ := c.Open(ctx, kept, b.static.Public())

	now = now.Add(IdleFor + time.Second)
	s.Sweep()
	if _, err := os.Stat(filepath.Join(s.dir, "pending", stale)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a stale pending key is still there")
	}
	for _, p := range []string{filepath.Join("pending", fresh), filepath.Join("kept", kept)} {
		if _, err := os.Stat(filepath.Join(s.dir, p)); err != nil {
			t.Fatalf("%s went: %v", p, err)
		}
	}
	if _, err := c.Seal(ctx, sess, []byte("x")); !errors.Is(err, ErrUnknownSession) {
		t.Fatal("an idle session outlived the sweep")
	}
}

// The socket: the peer's user is checked, and the client dials again after
// ftwkeysd restarts. A session does not survive the restart.
func TestTheSocketChecksThePeerAndSurvivesARestart(t *testing.T) {
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	s, _, _ := newTestServer(t)
	serve := func(srv *Server) net.Listener {
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(ln) }()
		return ln
	}
	ln := serve(s)
	c := Dial(path)
	defer c.Close()
	kid, _, err := c.New(ctx)
	if err != nil {
		t.Fatalf("own user refused: %v", err)
	}
	_ = c.Keep(ctx, kid)
	b := newBox(t)
	sess, _, err := c.Open(ctx, kid, b.static.Public())
	if err != nil {
		t.Fatal(err)
	}

	// Restart: same state directory, new process, sessions gone.
	_ = ln.Close()
	_ = c.Close()
	s2, err := NewServer(s.dir, s.sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln = serve(s2)
	if _, err := c.Seal(ctx, sess, []byte("x")); !errors.Is(err, ErrUnknownSession) {
		t.Fatalf("a session survived the restart: %v", err)
	}
	if _, _, err := c.Open(ctx, kid, b.static.Public()); err != nil {
		t.Fatalf("a kept key did not survive the restart: %v", err)
	}

	// Another user is turned away before a single request is read.
	_ = ln.Close()
	_ = c.Close()
	s3, _ := NewServer(s.dir, s.sealer, nil)
	s3.PeerUID = os.Getuid() + 1
	ln = serve(s3)
	defer ln.Close()
	if _, _, err := c.New(ctx); err == nil {
		t.Fatal("a peer of another user was served")
	}
}

// Many sessions at once, each kept in order by its caller.
func TestManySessionsAtOnce(t *testing.T) {
	s, _, _ := newTestServer(t)
	c := s.Local()
	kid, _, _ := c.New(ctx)
	_ = c.Keep(ctx, kid)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := newBox(t)
			sess, msg1, err := c.Open(ctx, kid, b.static.Public())
			if err != nil {
				t.Error(err)
				return
			}
			msg2, tr, _ := b.answer(t, msg1)
			if err := c.Finish(ctx, sess, msg2); err != nil {
				t.Error(err)
				return
			}
			for i := range 20 {
				msg, err := c.Seal(ctx, sess, []byte{byte(i)})
				if err != nil {
					t.Error(err)
					return
				}
				if got, err := tr.Decrypt(msg); err != nil || got[0] != byte(i) {
					t.Errorf("frame %d: %v", i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// offerFor is a well-formed offer for key pub, as FTW Cloud makes one.
func offerFor(t *testing.T, pub []byte, edit func(*protocol.GrantOffer)) []byte {
	t.Helper()
	o := protocol.GrantOffer{
		V: protocol.GrantOfferVersion, Key: pub, Role: protocol.RoleAgent,
		Client: "Claude", ClientID: "https://claude.ai/oauth/mcp-oauth-client-metadata", ClientHost: "claude.ai",
		Scopes: []string{"ftw.live.read"}, TTLS: 3600, Ticket: "t", Code: "ABCD-EFGH",
		ExpMs: time.Now().Add(5 * time.Minute).UnixMilli(),
	}
	if edit != nil {
		edit(&o)
	}
	raw, err := encMode.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The offer key: made once, sealed, the same after a restart. It signs an
// offer only for a key that the keys part made and that waits for approval,
// for the agent role and for no longer than an offer may live. What it signs
// opens with the box's own check.
func TestTheOfferKeySignsOnlyOffersItCanVouchFor(t *testing.T) {
	s, sealer, logs := newTestServer(t)
	c := s.Local()
	pub, err := c.OfferKey(ctx)
	if err != nil || len(pub) != 65 || pub[0] != 4 {
		t.Fatalf("offer key: %x %v", pub, err)
	}
	kid, agent, _ := c.New(ctx)
	other, otherPub, _ := c.New(ctx)
	offer := offerFor(t, agent, nil)
	sig, err := c.SignOffer(ctx, kid, offer)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOffer(pub, offer, sig); err != nil {
		t.Fatal(err)
	}
	so := protocol.SignedOffer{O: offer, Kid: OfferKid(pub), Sig: sig}
	if _, err := protocol.OpenOffer(map[string][]byte{OfferKid(pub): pub}, so, time.Now().UnixMilli()); err != nil {
		t.Fatalf("the box does not open the offer: %v", err)
	}
	if VerifyOffer(pub, offerFor(t, agent, func(o *protocol.GrantOffer) { o.Code = "OTHER" }), sig) == nil {
		t.Fatal("a signature verified for another offer")
	}

	type extra struct {
		protocol.GrantOffer
		X int `cbor:"x"`
	}
	withExtra, _ := encMode.Marshal(extra{GrantOffer: protocol.GrantOffer{
		V: 1, Key: agent, Role: protocol.RoleAgent, ExpMs: time.Now().Add(time.Minute).UnixMilli()}, X: 1})
	refused := map[string]struct {
		kid   string
		offer []byte
	}{
		"empty":               {kid, nil},
		"not CBOR":            {kid, []byte("{}")},
		"an unknown field":    {kid, withExtra},
		"another pending key": {other, offer},
		"another key's offer": {kid, offerFor(t, otherPub, nil)},
		"a made-up key":       {kid, offerFor(t, bytes.Repeat([]byte{1}, 32), nil)},
		"no kid":              {"", offer},
		"the support role":    {kid, offerFor(t, agent, func(o *protocol.GrantOffer) { o.Role = protocol.RoleSupport })},
		"the owner role":      {kid, offerFor(t, agent, func(o *protocol.GrantOffer) { o.Role = protocol.RoleOwner })},
		"another version":     {kid, offerFor(t, agent, func(o *protocol.GrantOffer) { o.V = 2 })},
		"an expired offer":    {kid, offerFor(t, agent, func(o *protocol.GrantOffer) { o.ExpMs = time.Now().UnixMilli() - 1 })},
		"an offer for too long": {kid, offerFor(t, agent, func(o *protocol.GrantOffer) {
			o.ExpMs = time.Now().UnixMilli() + protocol.OfferTTLMs + 60_000
		})},
	}
	for name, r := range refused {
		if _, err := c.SignOffer(ctx, r.kid, r.offer); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A key the owner approved is no longer offered.
	if err := c.Keep(ctx, kid); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SignOffer(ctx, kid, offer); !errors.Is(err, ErrRefused) {
		t.Fatalf("a kept key's offer: %v", err)
	}

	// A restart reads the same key back; it is not on disk in the clear.
	s2, err := NewServer(s.dir, sealer, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _ := s2.Local().OfferKey(ctx)
	if !bytes.Equal(pub, pub2) {
		t.Fatal("the offer key changed across a restart")
	}
	raw, _ := os.ReadFile(filepath.Join(s.dir, "offer.key"))
	d, _ := s.offer.(*localOfferKey).key.Bytes()
	if bytes.Contains(raw, d) || bytes.Contains(logs.Bytes(), d) || bytes.Contains(logs.Bytes(), []byte(hex.EncodeToString(d))) {
		t.Fatal("the offer key's secret is on disk or in the log")
	}
	// Its data key is bound to the offer key, not to any agent kid.
	var rec offerRecord
	_ = decMode.Unmarshal(raw, &rec)
	if _, err := sealer.Unwrap(ctx, "AAAAAAAAAAAAAAAAAAAAAA", rec.DEK); err == nil {
		t.Fatal("the offer key's data key opens under an agent kid")
	}
}

// fakeSigner stands in for an asymmetric KMS key.
type fakeSigner struct {
	key   *ecdsa.PrivateKey
	wrong bool
	calls int
}

func (f *fakeSigner) PublicKey(_ context.Context, keyID string) ([]byte, error) {
	if keyID != "alias/ftw-cloud-offer-key" {
		return nil, errors.New("NotFoundException")
	}
	return x509.MarshalPKIXPublicKey(&f.key.PublicKey)
}

func (f *fakeSigner) Sign(_ context.Context, _ string, digest []byte) ([]byte, error) {
	f.calls++
	if f.wrong {
		digest = bytes.Repeat([]byte{1}, 32)
	}
	return ecdsa.SignASN1(rand.Reader, f.key, digest)
}

// In production the offer key is in KMS: the keys part asks KMS to sign,
// checks the answer and never holds the private half.
func TestTheOfferKeyCanLiveInKMS(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer := &fakeSigner{key: priv}
	k, err := NewKMSOfferKey(ctx, signer, "alias/ftw-cloud-offer-key")
	if err != nil {
		t.Fatal(err)
	}
	sealer, _ := FileSealerFromKey(bytes.Repeat([]byte{7}, dataKeyBytes))
	s, err := NewServer(t.TempDir(), sealer, nil, WithOfferKey(k))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.dir, "offer.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a local offer key was made beside the KMS one")
	}
	c := s.Local()
	pub, _ := c.OfferKey(ctx)
	want, _ := priv.PublicKey.Bytes()
	if !bytes.Equal(pub, want) {
		t.Fatal("the public half is not KMS's")
	}
	kid, agent, _ := c.New(ctx)
	offer := offerFor(t, agent, nil)
	sig, err := c.SignOffer(ctx, kid, offer)
	if err != nil || VerifyOffer(pub, offer, sig) != nil || signer.calls != 1 {
		t.Fatalf("signed through KMS: %v (%d calls)", err, signer.calls)
	}
	// A refused offer never reaches KMS, and a wrong answer from KMS is not
	// passed on.
	_, _ = c.SignOffer(ctx, kid, offerFor(t, agent, func(o *protocol.GrantOffer) { o.Role = protocol.RoleSupport }))
	if signer.calls != 1 {
		t.Fatal("a refused offer reached KMS")
	}
	signer.wrong = true
	if _, err := c.SignOffer(ctx, kid, offer); err == nil {
		t.Fatal("a signature that does not verify was passed on")
	}
	if _, err := NewKMSOfferKey(ctx, signer, "alias/another"); err == nil {
		t.Fatal("a missing key was taken")
	}
}

// Only a unix socket's peer is served.
func TestServeRefusesAConnectionThatIsNotUnix(t *testing.T) {
	s, _, _ := newTestServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = s.Serve(ln) }()
	c := newClient(func() (net.Conn, error) { return net.Dial("tcp", ln.Addr().String()) })
	defer c.Close()
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, _, err := c.New(tctx); err == nil {
		t.Fatal("a TCP peer was served")
	}
}

func TestOfferKidNamesTheKey(t *testing.T) {
	a, b := bytes.Repeat([]byte{4}, 65), bytes.Repeat([]byte{5}, 65)
	if len(OfferKid(a)) != 16 || OfferKid(a) == OfferKid(b) || OfferKid(a) != OfferKid(bytes.Clone(a)) {
		t.Fatal("kid")
	}
}
