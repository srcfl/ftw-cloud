package registry

import (
	"testing"
	"time"
)

// A device holds one token; a new one replaces the old, and only an unexpired
// hash is found.
func TestADeviceHoldsOneToken(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("h1", []byte("pk"), now)
	row := TokenRow{Home: "h1", DeviceID: "phone", Epoch: 2, Expires: now.Add(time.Hour)}
	if err := r.TokenIssue(row, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := r.TokenIssue(row, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.TokenLookup([]byte("first"), now); ok {
		t.Fatal("the replaced token still reads")
	}
	got, ok, err := r.TokenLookup([]byte("second"), now)
	if err != nil || !ok || got.Home != "h1" || got.DeviceID != "phone" || got.Epoch != 2 {
		t.Fatalf("lookup: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := r.TokenLookup([]byte("second"), now.Add(time.Hour)); ok {
		t.Fatal("an expired token was found")
	}
	if err := r.TokenExpire(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.TokenLookup([]byte("second"), now); ok {
		t.Fatal("upkeep left an expired token")
	}
}

// A roster that drops a device or moves its epoch drops its token, a
// suspension drops it, and a purge takes every token of the home.
func TestTokensGoWithTheirRosterEntry(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("h1", []byte("pk"), now)
	issue := func(id string, epoch uint64) {
		if err := r.TokenIssue(TokenRow{Home: "h1", DeviceID: id, Epoch: epoch, Expires: now.Add(time.Hour)}, []byte(id)); err != nil {
			t.Fatal(err)
		}
	}
	found := func(id string) bool {
		_, ok, _ := r.TokenLookup([]byte(id), now)
		return ok
	}
	issue("kept", 1)
	issue("moved", 1)
	issue("dropped", 1)
	issue("suspended", 1)
	keep := map[string]uint64{"kept": 1, "moved": 2, "suspended": 1}
	if err := r.TokenPrune("h1", func(id string, epoch uint64) bool { e, ok := keep[id]; return ok && e == epoch }); err != nil {
		t.Fatal(err)
	}
	if !found("kept") || found("moved") || found("dropped") {
		t.Fatal("the prune kept the wrong tokens")
	}
	if err := r.TokenDrop("h1", "suspended"); err != nil || found("suspended") {
		t.Fatal("a dropped token still reads")
	}
	if err := r.Purge("h1", nil, now); err != nil || found("kept") {
		t.Fatal("a purge left a token")
	}
}
