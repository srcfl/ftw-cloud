package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The tiles of these tests: the one that starts 2026-10-12 12:00 UTC fills,
// and the clock reads 17:16.
const (
	tStart = int64(1_791_806_400_000)
	tSpan  = int64(43_200_000)
)

var tileNow = time.UnixMilli(tStart + (5*60+16)*60_000)

// windows has a value for every bucket up to the clock.
func windows() map[string][]protocol.HistorySample {
	out := map[string][]protocol.HistorySample{}
	for at := tStart - 5*tSpan; at < tileNow.UnixMilli(); at += 300_000 {
		for _, name := range cloudwire.TileSeries {
			out[name] = append(out[name], protocol.HistorySample{StartMs: at, W: float64(at / 300_000 % 977)})
		}
	}
	return out
}

func closedTile(start int64) cloudwire.Tiles {
	c := protocol.PackTile(cloudwire.TileRes, 1, start, cloudwire.TileSeries, windows(), start+tSpan)
	return cloudwire.Tiles{TileID: c.TileID, Etag: c.Etag, Res: c.Res, StartMs: c.StartMs, StepMs: c.StepMs,
		Series: c.Series, Data: c.Data}
}

// piece is points [from, to) of the tile at start, as the box cuts them.
func piece(start int64, from, to int) cloudwire.Tiles {
	c := protocol.PackTile(cloudwire.TileRes, 1, start, cloudwire.TileSeries, windows(), tileNow.UnixMilli())
	return cloudwire.Piece(c, from, to)
}

// env stands for the box's signed envelope; the store holds bytes and reads
// what the uplink checked.
func env(b cloudwire.Tiles, seq uint64) []byte {
	return []byte(b.TileID + "|" + b.Etag + "|" + time.UnixMilli(b.StartMs).UTC().Format("02T15:04") + "|" + string(rune('a'+seq%26)))
}

func tileHome(t *testing.T, grant ...string) (*Store, *Handle, *clock) {
	t.Helper()
	c := &clock{t: tileNow}
	s := New(c.now)
	box, err := s.For(Principal{Kind: Box, Home: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	box.Connected()
	if len(grant) == 0 {
		grant = []string{protocol.ScopeLiveRead, protocol.ScopeHistoryRead}
	}
	box.SetRoster(roster(1, grant...))
	return s, box, c
}

func put(t *testing.T, box *Handle, b cloudwire.Tiles, seq uint64) []byte {
	t.Helper()
	if err := b.Check(); err != nil {
		t.Fatal(err)
	}
	e := env(b, seq)
	if !kept(box, e, b, seq) {
		t.Fatalf("%s at %d not held", b.TileID, b.StartMs)
	}
	return e
}

// kept puts a tile sent as seq, and says whether the store kept it.
func kept(box *Handle, e []byte, b cloudwire.Tiles, seq uint64) bool {
	b.Seq = seq
	k, _ := box.PutTile(e, b)
	return k
}

func owner(t *testing.T, s *Store) *Handle {
	t.Helper()
	x, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestTheStoreAnswersWhatThePhoneLacksClosedFirstThenPiecesInOrder(t *testing.T) {
	s, box, _ := tileHome(t)
	older := put(t, box, closedTile(tStart-2*tSpan), 1)
	newer := put(t, box, closedTile(tStart-tSpan), 2)
	whole := put(t, box, piece(tStart, 0, 144), 3)
	app1 := put(t, box, piece(tStart, 62, 63), 4)
	app2 := put(t, box, piece(tStart, 63, 64), 5)

	got, err := owner(t, s).Tiles(nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := [][]byte{older, newer, whole, app1, app2}; !equalEnvs(got, want) {
		t.Fatalf("tiles.get {} answered %q", got)
	}
	// What the phone holds at the same etag stays home; a stale etag does
	// not.
	have := box.TilesHave()
	if len(have) != 2 || have[closedTile(tStart-tSpan).TileID] != closedTile(tStart-tSpan).Etag {
		t.Fatalf("have %v", have)
	}
	stale := map[string]string{closedTile(tStart - tSpan).TileID: closedTile(tStart - tSpan).Etag,
		closedTile(tStart - 2*tSpan).TileID: "00000000"}
	got, _ = owner(t, s).Tiles(stale)
	if want := [][]byte{older, whole, app1, app2}; !equalEnvs(got, want) {
		t.Fatalf("tiles.get with have answered %q", got)
	}
}

func TestAWholePieceStartsTheTileOverAndTheClosedTileEndsIt(t *testing.T) {
	s, box, _ := tileHome(t)
	put(t, box, piece(tStart, 0, 144), 1)
	put(t, box, piece(tStart, 62, 63), 2)
	whole := put(t, box, piece(tStart, 0, 144), 3)
	got, _ := owner(t, s).Tiles(nil)
	if !equalEnvs(got, [][]byte{whole}) {
		t.Fatalf("after a second whole piece: %q", got)
	}
	// The tile closes: its pieces go, and a late piece of it is refused.
	closed := closedTile(tStart)
	ce := env(closed, 4)
	if !kept(box, ce, closed, 4) {
		t.Fatal("closed tile not held")
	}
	if late := piece(tStart, 63, 64); kept(box, env(late, 5), late, 5) {
		t.Fatal("a piece of a closed tile was held")
	}
	got, _ = owner(t, s).Tiles(nil)
	if !equalEnvs(got, [][]byte{ce}) {
		t.Fatalf("after the tile closed: %q", got)
	}
	// The next tile's first piece starts a new trailing tile.
	next := closedTile(tStart + tSpan)
	next.Partial = true
	if !kept(box, env(next, 6), next, 6) {
		t.Fatal("the next tile's piece was refused")
	}
	if got, _ = owner(t, s).Tiles(nil); len(got) != 2 {
		t.Fatalf("%d tiles", len(got))
	}
}

func TestTilesAreBoundedPerHomeAndInAll(t *testing.T) {
	s, box, _ := tileHome(t)
	// The tile that ended 12:00 two days before ended more than 48 hours ago.
	if old := closedTile(tStart - 5*tSpan); kept(box, env(old, 1), old, 1) {
		t.Fatal("a tile that ended more than 48 hours ago was held")
	}
	for i := int64(4); i >= 1; i-- {
		put(t, box, closedTile(tStart-i*tSpan), uint64(10-i))
	}
	// A whole piece and 15 appends; past them appends are refused, and what
	// is held still lays back into the tile, its first bucket included.
	put(t, box, piece(tStart, 0, 144), 20)
	for i := 1; i < cloudwire.TilePiecesMax; i++ {
		put(t, box, piece(tStart, 50+i, 51+i), uint64(20+i))
	}
	for i := 0; i < 4; i++ {
		if late := piece(tStart, 70+i, 71+i); kept(box, env(late, uint64(40+i)), late, uint64(40+i)) {
			t.Fatal("an append past the pieces a tile may have was held")
		}
	}
	got, _ := owner(t, s).Tiles(nil)
	if len(box.TilesHave()) != 4 || len(got)-4 != cloudwire.TilePiecesMax || !bytes.Equal(got[4], env(piece(tStart, 0, 144), 20)) {
		t.Fatalf("held %d closed and %d pieces", len(box.TilesHave()), len(got)-len(box.TilesHave()))
	}
	// The next whole piece starts the tile over.
	put(t, box, piece(tStart, 0, 144), 50)
	if got, _ = owner(t, s).Tiles(nil); len(got) != 5 {
		t.Fatalf("after a new whole piece, %d tiles", len(got))
	}

	// All homes together: past the cap a tile that adds bytes is dropped,
	// and one that frees more than it takes is held.
	for i := 1; i <= 3; i++ {
		put(t, box, piece(tStart, 50+i, 51+i), uint64(50+i))
	}
	s.tileBytesMax = s.TileBytes() + 10
	extra := closedTile(tStart - tSpan)
	extra.Data[0] ^= 1
	extra.Etag = protocol.EtagOf(extra.Data)
	if kept(box, bytes.Repeat([]byte{1}, 64), extra, 60) {
		t.Fatal("a tile past the store's cap was held")
	}
	before := s.TileBytes()
	whole := piece(tStart, 0, 144)
	if !kept(box, bytes.Repeat([]byte{2}, 40), whole, 61) || s.TileBytes() >= before {
		t.Fatal("a whole piece that frees bytes was refused at the cap")
	}
}

func TestTilesOutliveTheHourOfSilenceAndGoAfter48Hours(t *testing.T) {
	s, box, c := tileHome(t)
	_ = box.Put(cloudwire.MsgLive, []byte("live"), 1, true)
	put(t, box, closedTile(tStart-tSpan), 2)
	put(t, box, piece(tStart, 0, 144), 3)
	box.Disconnected(1)

	c.t = tileNow.Add(2 * time.Hour)
	s.Sweep()
	snap, _ := owner(t, s).Snapshot()
	got, _ := owner(t, s).Tiles(nil)
	if len(snap.Envelopes) != 0 || len(got) != 2 {
		t.Fatalf("after two silent hours: %d readings, %d tiles", len(snap.Envelopes), len(got))
	}
	// The closed tile ended at 12:00; two days later it is gone, and the
	// trailing one, which ends at midnight, stays until then.
	c.t = time.UnixMilli(tStart + cloudwire.TileKeepMs + time.Minute.Milliseconds())
	// The box sent a roster since, or no phone would be let in at all.
	box.SetRoster(roster(2, protocol.ScopeLiveRead, protocol.ScopeHistoryRead))
	s.Sweep()
	got, _ = owner(t, s).Tiles(nil)
	if len(got) != 1 || len(box.TilesHave()) != 0 {
		t.Fatalf("48 hours after the closed tile ended: %d tiles", len(got))
	}
	// A tile from the future is refused.
	future := piece(tStart, 0, 1)
	c.t = time.UnixMilli(tStart - 2*tSpan)
	if kept(box, env(future, 9), future, 9) {
		t.Fatal("a tile more than a tile ahead of the clock was held")
	}
}

func TestRevokePurgeOrAGrantWithoutHistoryDropsTheTiles(t *testing.T) {
	cases := map[string]func(*Store, *Handle){
		"copy withdrawn": func(_ *Store, box *Handle) {
			r := roster(2)
			r.Grant.Purposes = nil
			box.SetRoster(r)
		},
		"history taken out": func(_ *Store, box *Handle) { box.SetRoster(roster(2, protocol.ScopeLiveRead)) },
		"copy dropped":      func(_ *Store, box *Handle) { box.DropCopy() },
		"home purged":       func(_ *Store, box *Handle) { box.Delete() },
		"home forgotten":    func(s *Store, _ *Handle) { s.Forget("h1") },
	}
	for name, end := range cases {
		t.Run(name, func(t *testing.T) {
			s, box, _ := tileHome(t)
			put(t, box, closedTile(tStart-tSpan), 1)
			put(t, box, piece(tStart, 0, 144), 2)
			if s.TileBytes() == 0 {
				t.Fatal("nothing counted")
			}
			end(s, box)
			if s.TileBytes() != 0 || len(box.TilesHave()) != 0 {
				t.Fatalf("%d bytes of tiles left", s.TileBytes())
			}
			if x, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey}); err == nil {
				if got, _ := x.Tiles(nil); len(got) != 0 {
					t.Fatalf("%d tiles still served", len(got))
				}
			}
			// And none is taken while it lasts.
			if b := closedTile(tStart - tSpan); name == "history taken out" && kept(box, env(b, 3), b, 3) {
				t.Fatal("a tile was held under a grant without ftw.history.read")
			}
		})
	}
}

func TestOnlyADeviceWithTheHistoryScopeReadsTiles(t *testing.T) {
	s, box, _ := tileHome(t)
	put(t, box, closedTile(tStart-tSpan), 1)
	viewer, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: viewerKey})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := viewer.Tiles(nil); err != nil || len(got) != 0 {
		t.Fatalf("a viewer without ftw.history.read read %d tiles", len(got))
	}
	if _, err := box.Tiles(nil); !errors.Is(err, ErrDenied) {
		t.Fatal("the box's handle reads tiles")
	}
	// The snapshot carries none: a phone asks.
	snap, _ := owner(t, s).Snapshot()
	if len(snap.Envelopes) != 0 {
		t.Fatalf("the snapshot carries %d envelopes", len(snap.Envelopes))
	}
	// Nor does a widget's token.
	_ = box.Put(cloudwire.MsgLive, []byte("live"), 2, true)
	if !kept(box, env(piece(tStart, 0, 144), 3), piece(tStart, 0, 144), 3) {
		t.Fatal("piece not held")
	}
	tok, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	now, _ := tok.Now()
	if !equalEnvs(now.Envelopes, [][]byte{[]byte("live")}) {
		t.Fatalf("a token read %q", now.Envelopes)
	}
}

// A phone reading the home gets each new tile as it comes, if it may read
// tiles.
func TestANewTileGoesToThePhonesThatMayReadIt(t *testing.T) {
	s, box, _ := tileHome(t)
	o, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: ownerKey})
	if err != nil {
		t.Fatal(err)
	}
	_, os, err := o.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Close()
	v, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: viewerKey})
	if err != nil {
		t.Fatal(err)
	}
	_, vs, err := v.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer vs.Close()
	e := put(t, box, piece(tStart, 0, 144), 1)
	select {
	case out := <-os.C():
		if !bytes.Equal(out.Env, e) {
			t.Fatal("the owner got other bytes")
		}
	case <-time.After(time.Second):
		t.Fatal("the owner got no tile")
	}
	select {
	case out := <-vs.C():
		t.Fatalf("the viewer got %q", out.Env)
	case <-time.After(50 * time.Millisecond):
	}
}

func equalEnvs(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// An agent reads history from the box, never from these tiles: its handle
// is refused, and its session gets none as they come.
func TestAnAgentGetsNoTiles(t *testing.T) {
	s, box, c := tileHome(t)
	r := rosterWithAgent(2, c.t.Add(time.Hour))
	r.Grant.Scopes = []string{protocol.ScopeLiveRead, protocol.ScopeHistoryRead}
	r.Devices[2].Agent.Scopes = []string{protocol.ScopeHistoryRead}
	box.SetRoster(r)
	put(t, box, closedTile(tStart-tSpan), 1)
	agent, err := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: agentKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Tiles(nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("an agent read tiles: %v", err)
	}
	_, sess, err := agent.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	put(t, box, piece(tStart, 0, 144), 2)
	select {
	case out := <-sess.C():
		t.Fatalf("an agent session got %q", out.Env)
	case <-time.After(50 * time.Millisecond):
	}
}

// The box sends a closed tile again when its ledger changed: the later one
// replaces the first, and an older one that comes late replaces nothing.
// A piece that comes after one the box sent later is dropped too.
func TestAClosedTileIsReplacedOnlyByOneSentLater(t *testing.T) {
	s, box, _ := tileHome(t)
	first := closedTile(tStart - tSpan)
	fixed := first
	fixed.Data = bytes.Clone(first.Data)
	fixed.Data[0] ^= 1
	fixed.Etag = protocol.EtagOf(fixed.Data)
	put(t, box, first, 10)
	put(t, box, fixed, 20)
	if box.TilesHave()[first.TileID] != fixed.Etag {
		t.Fatal("a later closed tile did not replace the first")
	}
	if kept(box, env(first, 15), first, 15) || box.TilesHave()[first.TileID] != fixed.Etag {
		t.Fatal("an older closed tile replaced a later one")
	}
	put(t, box, piece(tStart, 0, 144), 30)
	put(t, box, piece(tStart, 62, 63), 32)
	if late := piece(tStart, 61, 62); kept(box, env(late, 31), late, 31) {
		t.Fatal("a piece sent before the one held was laid after it")
	}
	if got, _ := owner(t, s).Tiles(map[string]string{first.TileID: fixed.Etag}); len(got) != 2 {
		t.Fatalf("%d pieces", len(got))
	}
}

// One home holds at most TileBytesPerHome, whatever room the store has.
func TestAHomeHoldsAtMostItsShareOfTileBytes(t *testing.T) {
	_, box, _ := tileHome(t)
	big := func(n int) []byte { return bytes.Repeat([]byte{byte(n)}, 4000) }
	for i := int64(1); i <= 4; i++ {
		if !kept(box, big(int(i)), closedTile(tStart-i*tSpan), uint64(i)) {
			t.Fatalf("closed tile %d not held", i)
		}
	}
	held := 0
	for i := 0; i < cloudwire.TilePiecesMax; i++ {
		p := piece(tStart, 0, 144)
		if i > 0 {
			p = piece(tStart, 50+i, 51+i)
		}
		p.Seq = uint64(10 + i)
		k, full := box.PutTile(big(10+i), p)
		if k {
			held++
			continue
		}
		if !full {
			t.Fatal("a tile past the home's share was refused for another reason")
		}
		break
	}
	if total := 4*4000 + held*4000; total > TileBytesPerHome || held == cloudwire.TilePiecesMax {
		t.Fatalf("held %d pieces, %d bytes", held, total)
	}
}

// Once the roster runs out no phone may read the tiles, so they go.
func TestTilesGoWhenTheRosterRunsOut(t *testing.T) {
	s, box, c := tileHome(t)
	put(t, box, closedTile(tStart-tSpan), 1)
	box.Disconnected(1)
	c.t = c.t.Add(25 * time.Hour)
	s.Sweep()
	if s.TileBytes() != 0 || len(box.TilesHave()) != 0 {
		t.Fatalf("%d bytes of tiles after the roster ran out", s.TileBytes())
	}
}
