package registry

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Registry {
	r, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestAHomeIsClaimedOnceAndKeepsItsRoster(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	if err := r.Claim("h1", []byte("pk"), now); err != nil {
		t.Fatal(err)
	}
	if err := r.Claim("h1", []byte("pk"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := r.SetRoster("h1", 3, []byte("grant"), []byte("signed roster"), now); err != nil {
		t.Fatal(err)
	}
	_ = r.SetRoster("h1", 2, []byte("grant"), []byte("older"), now) // ignored
	h, ok, err := r.Get("h1")
	if err != nil || !ok || h.RosterSeq != 3 || string(h.Roster) != "signed roster" || !h.CreatedAt.Equal(now) {
		t.Fatalf("home %+v, %v, %v", h, ok, err)
	}
}

// A purged home leaves only a tombstone, and its box cannot claim it again.
func TestAPurgeLeavesATombstone(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("h1", []byte("pk"), now)
	_ = r.SetRoster("h1", 1, []byte("grant-1"), []byte("roster"), now)
	if err := r.Purge("h1", []byte("grant-1"), now); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r.Get("h1"); ok {
		t.Fatal("the home survived its purge")
	}
	if string(r.TombstoneGrant("h1")) != "grant-1" {
		t.Fatal("no tombstone")
	}
	if err := r.Claim("h1", []byte("pk"), now); !errors.Is(err, ErrPurged) {
		t.Fatalf("claim after purge: %v", err)
	}
}

func TestHomesWithoutARosterExpire(t *testing.T) {
	r := open(t)
	now := time.Unix(1_791_820_800, 0)
	_ = r.Claim("silent", []byte("a"), now)
	_ = r.Claim("talks", []byte("b"), now)
	_ = r.SetRoster("talks", 1, nil, []byte("r"), now)
	gone, err := r.Expire(now.Add(NewHomeGrace + time.Minute))
	if err != nil || len(gone) != 1 || gone[0] != "silent" {
		t.Fatalf("after a day: %v %v", gone, err)
	}
	gone, _ = r.Expire(now.Add(RosterGrace + time.Minute))
	if len(gone) != 1 || gone[0] != "talks" {
		t.Fatalf("after 90 days: %v", gone)
	}
}
