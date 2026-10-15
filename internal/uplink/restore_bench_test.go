package uplink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// BenchmarkRestore10k is a deploy's start with 10,000 homes in the
// registry: every signed roster read back and checked before the service
// listens. go test -run XXX -bench Restore10k -benchtime 3x ./internal/uplink
func BenchmarkRestore10k(b *testing.B) {
	reg, err := registry.Open(filepath.Join(b.TempDir(), "registry.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer reg.Close()
	now := time.Now()
	for range 10_000 {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
		home := cloudwire.HomeID(pk)
		bx := &box{key: key, pk: pk, home: home, boot: []byte{1, 2, 3, 4, 5, 6, 7, 8}}
		env, err := cloudwire.Seal(key, home, cloudwire.MsgRoster, bx.roster())
		if err != nil {
			b.Fatal(err)
		}
		raw, _ := env.Encode()
		if err := reg.Claim(home, pk, now); err != nil {
			b.Fatal(err)
		}
		if err := reg.SetRoster(home, 1, nil, raw, now); err != nil {
			b.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b.ResetTimer()
	for range b.N {
		up := New(store.New(nil), reg, nil, log)
		if n, err := up.Restore(); err != nil || n != 10_000 {
			b.Fatalf("restored %d, %v", n, err)
		}
	}
}
