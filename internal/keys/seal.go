package keys

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// A Sealer makes and unwraps the data keys that seal agent keys at rest:
// envelope encryption, one data key per agent key. In production the data
// keys are wrapped by one AWS KMS key that only ftwkeysd's role may use; in
// development, by a key in a local file.
type Sealer interface {
	// DataKey returns a new data key and its wrapped form, bound to kid.
	DataKey(ctx context.Context, kid string) (plain, wrapped []byte, err error)
	// Unwrap returns the data key wrapped for kid.
	Unwrap(ctx context.Context, kid string, wrapped []byte) ([]byte, error)
}

// dataKeyBytes is an AES-256 key.
const dataKeyBytes = 32

// KMS is the part of AWS KMS the sealer uses. cmd/ftwkeysd adapts the AWS
// SDK to it, so this package and its tests do not link the SDK.
type KMS interface {
	// GenerateDataKey asks for a new AES-256 data key under keyID with the
	// encryption context, as kms:GenerateDataKey.
	GenerateDataKey(ctx context.Context, keyID string, context map[string]string) (plain, blob []byte, err error)
	// Decrypt unwraps blob under keyID with the same context, as
	// kms:Decrypt.
	Decrypt(ctx context.Context, keyID string, blob []byte, context map[string]string) ([]byte, error)
}

// KMSSealer wraps data keys with one AWS KMS key. The encryption context
// names the purpose and the key id, so a wrapped data key opens only for the
// agent key it was made for, and the key policy can require the purpose.
type KMSSealer struct {
	KMS   KMS
	KeyID string
}

// EncryptionContextPurpose is the purpose in every encryption context. The
// KMS key policy allows ftwkeysd's role only with it.
const EncryptionContextPurpose = "ftw-agent-key"

func kmsContext(kid string) map[string]string {
	return map[string]string{"purpose": EncryptionContextPurpose, "kid": kid}
}

func (s KMSSealer) DataKey(ctx context.Context, kid string) ([]byte, []byte, error) {
	plain, blob, err := s.KMS.GenerateDataKey(ctx, s.KeyID, kmsContext(kid))
	if err != nil {
		return nil, nil, err
	}
	if len(plain) != dataKeyBytes || len(blob) == 0 {
		return nil, nil, errors.New("keys: KMS returned a data key of the wrong size")
	}
	return plain, blob, nil
}

func (s KMSSealer) Unwrap(ctx context.Context, kid string, wrapped []byte) ([]byte, error) {
	plain, err := s.KMS.Decrypt(ctx, s.KeyID, wrapped, kmsContext(kid))
	if err != nil {
		return nil, err
	}
	if len(plain) != dataKeyBytes {
		return nil, errors.New("keys: KMS returned a data key of the wrong size")
	}
	return plain, nil
}

// FileSealer wraps data keys with a 32-byte key from a local file. It is for
// development and tests: whoever reads the file and the state directory has
// every agent key.
type FileSealer struct {
	aead cipher.AEAD
}

// NewFileSealer reads a key file of 32 bytes, raw or as 64 hex digits.
func NewFileSealer(path string) (*FileSealer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("file key: %w", err)
	}
	key := raw
	if s := strings.TrimSpace(string(raw)); len(s) == 2*dataKeyBytes {
		if key, err = hex.DecodeString(s); err != nil {
			return nil, fmt.Errorf("file key: %w", err)
		}
	}
	if len(key) != dataKeyBytes {
		return nil, fmt.Errorf("file key: %s holds %d bytes, want %d", path, len(key), dataKeyBytes)
	}
	return FileSealerFromKey(key)
}

// FileSealerFromKey is a FileSealer around key.
func FileSealerFromKey(key []byte) (*FileSealer, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return &FileSealer{aead: aead}, nil
}

// MakeFileKey writes a new file key that only its owner can read, and never
// over an existing file.
func MakeFileKey(path string) error {
	key := make([]byte, dataKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(hex.EncodeToString(key) + "\n")); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func fileAAD(kid string) []byte { return []byte("ftw.agent-dek.v1\x00" + kid) }

func (s *FileSealer) DataKey(_ context.Context, kid string) ([]byte, []byte, error) {
	plain := make([]byte, dataKeyBytes)
	if _, err := rand.Read(plain); err != nil {
		return nil, nil, err
	}
	wrapped, err := seal(s.aead, plain, fileAAD(kid))
	if err != nil {
		return nil, nil, err
	}
	return plain, wrapped, nil
}

func (s *FileSealer) Unwrap(_ context.Context, kid string, wrapped []byte) ([]byte, error) {
	return open(s.aead, wrapped, fileAAD(kid))
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal is nonce ‖ AES-GCM(plain, aad).
func seal(aead cipher.AEAD, plain, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, aad), nil
}

func open(aead cipher.AEAD, sealed, aad []byte) ([]byte, error) {
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("keys: sealed data too short")
	}
	n := aead.NonceSize()
	return aead.Open(nil, sealed[:n], sealed[n:], aad)
}

// wipe overwrites a secret held in a slice. Go may have copied it elsewhere,
// so this narrows how long a key lingers in memory; it does not promise
// that no copy is left.
func wipe(b []byte) {
	clear(b)
}
