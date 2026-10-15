package keys

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw/go/protocol"
)

// The offer key. FTW Cloud's consent page hands the owner's app a grant
// offer: the agent's public key and what its client asks for. The app shows
// it before Face ID, so it must know the offer came from FTW Cloud and not
// from a page that copied the look. The keys part signs each offer with one
// P-256 key that Core and the apps pin.
//
// In production the key is an AWS KMS key of its own (ECC_NIST_P256,
// SIGN_VERIFY): its private half never leaves KMS, and only ftwkeysd's role
// may sign with it. In development and tests it is a local P-256 key, sealed
// in the state directory like an agent key.
//
// The keys part signs only an offer it can vouch for: a well-formed
// protocol.GrantOffer for the agent role, short-lived, whose key is one it
// made and that is still waiting for approval. So ftwcloudd cannot get an
// owner to approve a key that ftwcloudd holds.

// OfferTag starts every signed offer array.
const OfferTag = protocol.OfferTag

// offerKid binds the local offer key's data key in the sealer's context. It
// is no agent kid's shape, so no agent operation can name it.
const offerKid = "offer-key"

const (
	opOfferPub  = "offer.pub"  // the offer key's public half, SEC1 uncompressed
	opOfferSign = "offer.sign" // sign offer d for pending key kid; answers r ‖ s
)

// maxOffer bounds one offer's CBOR.
const maxOffer = 8 << 10

// An OfferSigner holds the offer key.
type OfferSigner interface {
	// Public is the key's public half, SEC1 uncompressed.
	Public() []byte
	// Sign signs a SHA-256 digest and answers r ‖ s.
	Sign(ctx context.Context, digest []byte) ([]byte, error)
}

// OfferKid names an offer key by its public half (protocol.OfferKid). Core
// and the apps pin keys by it, so a new key can be added beside the old one.
func OfferKid(pub []byte) string { return protocol.OfferKid(pub) }

// OfferBytes is what the offer key signs: the deterministic CBOR array
// [OfferTag, offer], where offer is the offer's own CBOR encoding.
func OfferBytes(offer []byte) ([]byte, error) { return protocol.OfferBytes(offer) }

// VerifyOffer checks an offer's signature, r ‖ s, against the offer key's
// public half. The app does the same with the key it pins.
func VerifyOffer(pub, offer, sig []byte) error {
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
	if err != nil || len(sig) != 64 {
		return errors.New("keys: not an offer signature")
	}
	msg, err := OfferBytes(offer)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("keys: the offer signature does not verify")
	}
	return nil
}

// offerDec reads an offer as the box does: a key it does not know, or a key
// twice, is refused.
var offerDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxArrayElements:  64,
		MaxMapPairs:       32,
		MaxNestedLevels:   4,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// signOffer signs offer if the keys part can vouch for it: a GrantOffer of
// this version, for the agent role, good for no longer than OfferTTLMs, whose
// key is kid's and kid is still pending.
func (s *Server) signOffer(kid string, offer []byte) ([]byte, error) {
	if s.offer == nil || !validKid(kid) || len(offer) == 0 || len(offer) > maxOffer {
		return nil, ErrRefused
	}
	var o protocol.GrantOffer
	if err := offerDec.Unmarshal(offer, &o); err != nil {
		return nil, ErrRefused
	}
	now := s.now().UnixMilli()
	if o.V != protocol.GrantOfferVersion || o.Role != protocol.RoleAgent ||
		o.ExpMs <= now || o.ExpMs > now+protocol.OfferTTLMs {
		return nil, ErrRefused
	}
	pub, err := s.pendingPub(kid)
	if err != nil || !bytes.Equal(pub, o.Key) {
		return nil, ErrRefused
	}
	msg, err := OfferBytes(offer)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(msg)
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	sig, err := s.offer.Sign(ctx, digest[:])
	if err != nil {
		s.log.Warn("could not sign an offer", "err", err)
		return nil, err
	}
	return sig, nil
}

// pendingPub is the public half of a key still waiting for approval.
func (s *Server) pendingPub(kid string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "pending", kid))
	if err != nil {
		return nil, ErrUnknownKey
	}
	var rec record
	if err := decMode.Unmarshal(raw, &rec); err != nil || rec.Kid != kid {
		return nil, ErrUnknownKey
	}
	return rec.Pub, nil
}

func (s *Server) offerPub() ([]byte, error) {
	if s.offer == nil {
		return nil, ErrRefused
	}
	return bytes.Clone(s.offer.Public()), nil
}

// OfferKey is the offer key's public half, SEC1 uncompressed.
func (c *Client) OfferKey(ctx context.Context) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opOfferPub})
	return resp.Pub, err
}

// SignOffer signs one offer's CBOR with the offer key. The offer's key must
// be the public half of kid, a key New made that is not yet kept.
func (c *Client) SignOffer(ctx context.Context, kid string, offer []byte) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opOfferSign, Kid: kid, D: offer})
	return resp.D, err
}

// --------------------------------------------------------------------------
// The offer key in KMS
// --------------------------------------------------------------------------

// KMSSigner is the part of AWS KMS the offer key uses. cmd/ftwkeysd adapts
// the AWS SDK to it.
type KMSSigner interface {
	// PublicKey answers the key's public half as DER SubjectPublicKeyInfo, as
	// kms:GetPublicKey. It refuses a key that is not ECC_NIST_P256 for
	// signing.
	PublicKey(ctx context.Context, keyID string) ([]byte, error)
	// Sign signs a SHA-256 digest with ECDSA_SHA_256, as kms:Sign with
	// MessageType DIGEST, and answers the DER signature.
	Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error)
}

type kmsOfferKey struct {
	kms KMSSigner
	id  string
	key *ecdsa.PublicKey
	pub []byte
}

// NewKMSOfferKey is the offer key held in KMS under keyID. It reads the
// public half once.
func NewKMSOfferKey(ctx context.Context, k KMSSigner, keyID string) (OfferSigner, error) {
	der, err := k.PublicKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("keys: offer key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("keys: offer key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("keys: the offer key is not a P-256 key")
	}
	pub, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	return &kmsOfferKey{kms: k, id: keyID, key: key, pub: pub}, nil
}

func (k *kmsOfferKey) Public() []byte { return k.pub }

// Sign asks KMS and checks what comes back against the public half.
func (k *kmsOfferKey) Sign(ctx context.Context, digest []byte) ([]byte, error) {
	der, err := k.kms.Sign(ctx, k.id, digest)
	if err != nil {
		return nil, err
	}
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil || !ecdsa.Verify(k.key, digest, sig.R, sig.S) {
		return nil, errors.New("keys: KMS answered a signature that does not verify")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// --------------------------------------------------------------------------
// The local offer key, for development and tests
// --------------------------------------------------------------------------

type localOfferKey struct {
	key *ecdsa.PrivateKey
	pub []byte
}

// offerRecord is the sealed local offer key on disk.
type offerRecord struct {
	V   int    `cbor:"v"`
	Pub []byte `cbor:"pub"`
	DEK []byte `cbor:"dek"`
	CT  []byte `cbor:"ct"`
}

// LocalOfferKey is an offer key in dir/offer.key, sealed by sealer, made on
// first use. It is for development and tests: production signs in KMS.
func LocalOfferKey(dir string, sealer Sealer, log *slog.Logger) (OfferSigner, error) {
	if log == nil {
		log = slog.Default()
	}
	path := filepath.Join(dir, "offer.key")
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return makeLocalOfferKey(path, sealer, log)
	}
	if err != nil {
		return nil, err
	}
	var rec offerRecord
	if err := decMode.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("keys: offer key: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, err := sealer.Unwrap(ctx, offerKid, rec.DEK)
	if err != nil {
		return nil, fmt.Errorf("keys: offer key: %w", err)
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	d, err := open(aead, rec.CT, append([]byte(OfferTag+"\x00"), rec.Pub...))
	if err != nil {
		return nil, errors.New("keys: the offer key does not open")
	}
	defer wipe(d)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, err
	}
	return &localOfferKey{key: key, pub: rec.Pub}, nil
}

func makeLocalOfferKey(path string, sealer Sealer, log *slog.Logger) (OfferSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	d, err := key.Bytes()
	if err != nil {
		return nil, err
	}
	defer wipe(d)
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, wrapped, err := sealer.DataKey(ctx, offerKid)
	if err != nil {
		return nil, err
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	ct, err := seal(aead, d, append([]byte(OfferTag+"\x00"), pub...))
	if err != nil {
		return nil, err
	}
	raw, err := encMode.Marshal(offerRecord{V: 1, Pub: pub, DEK: wrapped, CT: ct})
	if err != nil {
		return nil, err
	}
	if err := writeFile(path, raw); err != nil {
		return nil, err
	}
	log.Info("made a local offer key, for development only", "kid", OfferKid(pub),
		"pub", base64.RawURLEncoding.EncodeToString(pub))
	return &localOfferKey{key: key, pub: pub}, nil
}

func (k *localOfferKey) Public() []byte { return k.pub }

func (k *localOfferKey) Sign(_ context.Context, digest []byte) ([]byte, error) {
	r, sv, err := ecdsa.Sign(rand.Reader, k.key, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return sig, nil
}
