package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
)

// The offer key. FTW Cloud's consent page hands the owner's app a grant
// offer: the agent's public key and what its client asks for. The app shows
// it before Face ID, so it must know the offer came from FTW Cloud and not
// from a page that copied the look. The keys part signs each offer with one
// P-256 key that the app pins. It lives here, apart from the agent keys and
// sealed the same way, and it signs offers and nothing else: the signed
// bytes always start with OfferTag.

// OfferTag starts every signed offer array.
const OfferTag = "ftw.offer.v1"

// offerKid binds the offer key's data key in the sealer's context. It is no
// agent kid's shape, so no agent operation can name it.
const offerKid = "offer-key"

const (
	opOfferPub  = "offer.pub"  // the offer key's public half, SEC1 uncompressed
	opOfferSign = "offer.sign" // sign offer bytes d; answers r ‖ s
)

// OfferBytes is what the offer key signs: the deterministic CBOR array
// [OfferTag, offer], where offer is the offer's own CBOR encoding.
func OfferBytes(offer []byte) ([]byte, error) {
	return encMode.Marshal([]any{OfferTag, offer})
}

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

// offerRecord is the sealed offer key on disk.
type offerRecord struct {
	V   int    `cbor:"v"`
	Pub []byte `cbor:"pub"`
	DEK []byte `cbor:"dek"`
	CT  []byte `cbor:"ct"`
}

// loadOfferKey unseals the offer key, making it on first start. It stays in
// memory: it signs every consent page, and vouches only for what a page
// shows.
func (s *Server) loadOfferKey() error {
	path := filepath.Join(s.dir, "offer.key")
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s.makeOfferKey(path)
	}
	if err != nil {
		return err
	}
	var rec offerRecord
	if err := decMode.Unmarshal(raw, &rec); err != nil {
		return fmt.Errorf("keys: offer key: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, err := s.sealer.Unwrap(ctx, offerKid, rec.DEK)
	if err != nil {
		return fmt.Errorf("keys: offer key: %w", err)
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return err
	}
	d, err := open(aead, rec.CT, append([]byte(OfferTag+"\x00"), rec.Pub...))
	if err != nil {
		return errors.New("keys: the offer key does not open")
	}
	defer wipe(d)
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return err
	}
	s.offer = key
	return nil
}

func (s *Server) makeOfferKey(path string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return err
	}
	d, err := key.Bytes()
	if err != nil {
		return err
	}
	defer wipe(d)
	ctx, cancel := context.WithTimeout(context.Background(), unwrapTimeout)
	defer cancel()
	dek, wrapped, err := s.sealer.DataKey(ctx, offerKid)
	if err != nil {
		return err
	}
	defer wipe(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return err
	}
	ct, err := seal(aead, d, append([]byte(OfferTag+"\x00"), pub...))
	if err != nil {
		return err
	}
	raw, err := encMode.Marshal(offerRecord{V: 1, Pub: pub, DEK: wrapped, CT: ct})
	if err != nil {
		return err
	}
	if err := writeFile(path, raw); err != nil {
		return err
	}
	s.offer = key
	s.log.Info("made the offer key; pin its public half in the app", "pub", fmt.Sprintf("%x", pub))
	return nil
}

func (s *Server) offerPub() ([]byte, error) {
	if s.offer == nil {
		return nil, ErrRefused
	}
	return s.offer.PublicKey.Bytes()
}

func (s *Server) signOffer(offer []byte) ([]byte, error) {
	if s.offer == nil || len(offer) == 0 || len(offer) > 8<<10 {
		return nil, ErrRefused
	}
	msg, err := OfferBytes(offer)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(msg)
	r, sv, err := ecdsa.Sign(rand.Reader, s.offer, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return sig, nil
}

// OfferKey is the offer key's public half, SEC1 uncompressed.
func (c *Client) OfferKey(ctx context.Context) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opOfferPub})
	return resp.Pub, err
}

// SignOffer signs one offer's CBOR with the offer key.
func (c *Client) SignOffer(ctx context.Context, offer []byte) ([]byte, error) {
	resp, err := c.call(ctx, request{Op: opOfferSign, D: offer})
	return resp.D, err
}
