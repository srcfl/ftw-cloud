package mcp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type rosters map[string]registry.Home

func (r rosters) Get(home string) (registry.Home, bool, error) {
	h, ok := r[home]
	return h, ok, nil
}

// The box's Noise key is believed only from a roster its own key signed for
// its own home, and only in its right shape.
func TestTheBoxKeyComesOnlyFromTheBoxsSignedRoster(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	home := cloudwire.HomeID(pk)
	noise := bytes.Repeat([]byte{9}, 32)
	signed := func(k *ecdsa.PrivateKey, h string, n []byte) []byte {
		env, err := cloudwire.Seal(k, h, cloudwire.MsgRoster, struct {
			cloudwire.Roster
			Noise []byte `cbor:"noise"`
		}{cloudwire.Roster{RosterSeq: 1, TTLS: 60}, n})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := env.Encode()
		return raw
	}
	got, ok := RosterBoxKey(rosters{home: {ID: home, PK: pk, Roster: signed(key, home, noise)}})(home)
	if !ok || !bytes.Equal(got, noise) {
		t.Fatalf("the box's own roster: %x %v", got, ok)
	}
	for name, h := range map[string]registry.Home{
		"signed by another key": {ID: home, PK: pk, Roster: signed(other, home, noise)},
		"a short key":           {ID: home, PK: pk, Roster: signed(key, home, noise[:16])},
		"no roster":             {ID: home, PK: pk},
		"another home's key":    {ID: home, PK: func() []byte { p, _ := cloudwire.PublicKeyBytesOf(&other.PublicKey); return p }(), Roster: signed(key, home, noise)},
	} {
		if _, ok := RosterBoxKey(rosters{home: h})(home); ok {
			t.Errorf("%s: believed", name)
		}
	}
	if _, ok := RosterBoxKey(rosters{})(home); ok {
		t.Error("an unknown home has a key")
	}
}
