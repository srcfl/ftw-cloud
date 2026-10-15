package registry

import (
	"path/filepath"
	"testing"
	"time"
)

// Moving a home to another shard's registry takes every row it has, and
// leaves the other homes where they are.
func TestMoveToTakesEveryRowOfTheHomesItMoves(t *testing.T) {
	dir := t.TempDir()
	src, err := Open(filepath.Join(dir, "s1.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	now := time.UnixMilli(1_792_000_000_000)
	moving, staying, purged := "aaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccc"
	for _, h := range []string{moving, staying, purged} {
		if err := src.Claim(h, []byte("pk-"+h), now); err != nil {
			t.Fatal(err)
		}
		if err := src.SetRoster(h, 3, []byte("grant"), []byte("roster-"+h), now); err != nil {
			t.Fatal(err)
		}
	}
	_ = src.Suspend(moving, "watch", 2, now)
	_ = src.AwaySet(moving, now.Add(time.Minute))
	_ = src.PushRegister(PushReg{Home: moving, DeviceID: "phone", Epoch: 1, Token: []byte("apns"), Environment: "sandbox", Kind: "alert", At: now})
	_ = src.TokenIssue(TokenRow{Home: moving, DeviceID: "phone", Epoch: 1, Expires: now.Add(time.Hour)}, []byte("hash-of-token-32-bytes-long-ok!!"))
	_ = src.Purge(purged, []byte("grant"), now)
	keep := func(h string) bool { return h == moving || h == purged }

	dstPath := filepath.Join(dir, "s2.db")
	n, err := src.MoveTo(dstPath, keep, false)
	if err != nil || n != 2 {
		t.Fatalf("moved %d, %v", n, err)
	}
	dst, err := Open(dstPath)
	if err != nil {
		t.Fatal(err)
	}
	h, ok, _ := dst.Get(moving)
	if !ok || string(h.Roster) != "roster-"+moving || h.RosterSeq != 3 {
		t.Fatalf("home %+v, %v", h, ok)
	}
	if !dst.Suspended(moving, "watch", 2) {
		t.Fatal("the suspension stayed behind")
	}
	if regs, _ := dst.PushRegs(moving, "alert"); len(regs) != 1 {
		t.Fatalf("push %+v", regs)
	}
	if row, ok, _ := dst.TokenLookup([]byte("hash-of-token-32-bytes-long-ok!!"), now); !ok || row.Home != moving {
		t.Fatal("the token stayed behind")
	}
	if away, _ := dst.AwayAll(); len(away) != 1 || away[0].Home != moving {
		t.Fatalf("away %+v", away)
	}
	if _, ok, _ := dst.Tombstone(purged); !ok {
		t.Fatal("the tombstone stayed behind")
	}
	if _, ok, _ := dst.Get(staying); ok {
		t.Fatal("a home that stays was moved")
	}
	_ = dst.Close()
	// Still on the first shard until the second pass drops it.
	if _, ok, _ := src.Get(moving); !ok {
		t.Fatal("a copy dropped the home")
	}

	// What changed in between follows on the second pass, which drops; what
	// the destination heard since is not made older.
	_ = src.SetRoster(moving, 4, []byte("grant"), []byte("roster-4"), now)
	_ = src.PushRegister(PushReg{Home: moving, DeviceID: "watch", Epoch: 2, Token: []byte("apns-2"), Environment: "sandbox", Kind: "alert", At: now})
	if n, err := src.MoveTo(dstPath, keep, true); err != nil || n != 2 {
		t.Fatalf("moved %d, %v", n, err)
	}
	if _, ok, _ := src.Get(moving); ok || src.Suspended(moving, "watch", 2) {
		t.Fatal("the home is still on the first shard")
	}
	if _, ok, _ := src.Get(staying); !ok {
		t.Fatal("a home that stays was dropped")
	}
	dst, _ = Open(dstPath)
	defer dst.Close()
	if h, _, _ := dst.Get(moving); h.RosterSeq != 4 {
		t.Fatalf("the second pass left roster %d", h.RosterSeq)
	}
	if regs, _ := dst.PushRegs(moving, "alert"); len(regs) != 2 {
		t.Fatalf("push after the second pass %+v", regs)
	}
	// The destination hears roster 9 from the box; an older copy merged in
	// later leaves it.
	_ = dst.SetRoster(moving, 9, []byte("grant"), []byte("roster-9"), now)
	old, _ := Open(filepath.Join(dir, "old.db"))
	_ = old.Claim(moving, []byte("pk-"+moving), now)
	_ = old.SetRoster(moving, 5, []byte("grant"), []byte("roster-5"), now)
	if _, err := old.MoveTo(dstPath, keep, false); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()
	if h, _, _ := dst.Get(moving); h.RosterSeq != 9 {
		t.Fatalf("an older copy made the roster %d", h.RosterSeq)
	}
}

// A tombstone merged into a shard deletes the home it names there.
func TestMoveToCarriesAPurge(t *testing.T) {
	dir := t.TempDir()
	now := time.UnixMilli(1_792_000_000_000)
	home := "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	dstPath := filepath.Join(dir, "s2.db")
	dst, _ := Open(dstPath)
	_ = dst.Claim(home, []byte("pk"), now)
	_ = dst.SetRoster(home, 3, nil, []byte("roster"), now)
	_ = dst.Close()
	src, _ := Open(filepath.Join(dir, "s1.db"))
	defer src.Close()
	_ = src.Claim(home, []byte("pk"), now)
	_ = src.Purge(home, nil, now)
	if _, err := src.MoveTo(dstPath, func(string) bool { return true }, true); err != nil {
		t.Fatal(err)
	}
	dst, _ = Open(dstPath)
	defer dst.Close()
	if _, ok, _ := dst.Get(home); ok {
		t.Fatal("a purged home lives on at its new shard")
	}
	if _, ok, _ := dst.Tombstone(home); !ok {
		t.Fatal("no tombstone at the new shard")
	}
}
