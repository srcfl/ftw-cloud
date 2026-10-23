package store

import (
	"slices"
	"sort"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"

	"github.com/srcfl/ftw-cloud/internal/metrics"
)

// Tiles: each home's last 48 hours of 5-minute history, as the box signed
// it, so a phone can draw history while the box cannot answer
// (docs/protocol-cloud.md, tiles). They are dated history, never a reading
// of now, so they outlive the hour after which the box's readings go; and
// like the readings they live only in memory, only while the roster's grant
// serves a copy with ftw.history.read.

// TileBytesMax bounds what every home's tiles hold together, and
// TileBytesPerHome what one home's do. A home of five closed tiles and 16
// pieces holds about 20 KB, so the first is some 13,000 homes and at least
// 4,000 at the second; a shard takes on no more than 4,000. Past either, new
// tiles are dropped and counted.
const (
	TileBytesMax     = 256 << 20
	TileBytesPerHome = 64 << 10
)

var (
	tileBytesHeld  = metrics.Default.Gauge("ftwcloud_tile_bytes", "Bytes of history tiles held in memory, all homes.")
	dropTileOld    = metrics.Drop("tile_outside_48h")
	dropTileFull   = metrics.Drop("tile_memory_full")
	dropTileClosed = metrics.Drop("tile_piece_after_close")
	dropTilePieces = metrics.Drop("tile_too_many_pieces")
	dropTileHome   = metrics.Drop("tile_home_full")
	dropTileOlder  = metrics.Drop("tile_older_than_held")
)

// heldTile is one tiles envelope as the box sent it.
type heldTile struct {
	id    string
	etag  string
	start int64 // the tile's start, wall clock
	// wallMs and seq are when the box sent it, in the order it sent them:
	// wall time first, since seq starts again when the box does.
	wallMs int64
	seq    uint64
	env    []byte
}

// before says a was sent before b.
func (a heldTile) before(b heldTile) bool {
	return a.wallMs < b.wallMs || (a.wallMs == b.wallMs && a.seq < b.seq)
}

func (t heldTile) end() int64 {
	return t.start + protocol.ResolutionTileSpanMs[cloudwire.TileRes]
}

// tileSet is one home's tiles: each closed tile by id, and the pieces of the
// trailing tile in the order they came. A whole piece replaces the pieces
// before it, so laying them in order rebuilds the tile.
type tileSet struct {
	closed map[string]heldTile
	open   []heldTile
	bytes  int64
}

// PutTile keeps one tiles envelope the box signed, which the caller has
// verified and checked (cloudwire.Tiles.Check), and forwards it to the
// phones reading the home that may read tiles. kept is false when it was
// not kept: the grant holds no tiles, it is older than 48 hours or from the
// future, sent before what is held of its tile, a piece of a tile already
// closed, an append past the pieces a tile may have, or memory for tiles is
// full, which full says.
func (x *Handle) PutTile(env []byte, t cloudwire.Tiles) (kept, full bool) {
	if x.kind != Box {
		return false, false
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	x.h.lastSeen = x.s.now()
	if !x.h.holdsTilesLocked() {
		return false, false
	}
	now := x.s.now().UnixMilli()
	x.pruneTilesLocked(now)
	held := heldTile{id: t.TileID, etag: t.Etag, start: t.TileStart(), seq: t.Seq, env: env}
	if t.WallMs != nil {
		held.wallMs = *t.WallMs
	}
	if held.end() <= now-cloudwire.TileKeepMs || held.start > now+protocol.ResolutionTileSpanMs[cloudwire.TileRes] {
		dropTileOld.Inc()
		return false, false
	}
	ts := &x.h.tiles
	// What the tile replaces, first, so the memory check counts the net
	// change: a whole piece or a closed tile often frees more than it takes.
	var replaced int64
	dropOpen := false
	if !t.Partial {
		if old, ok := ts.closed[held.id]; ok {
			if held.before(old) {
				// An older version of a tile the box sent again since.
				dropTileOlder.Inc()
				return false, false
			}
			replaced += int64(len(old.env))
		}
		dropOpen = len(ts.open) > 0 && ts.open[0].id == held.id
	} else {
		if _, ok := ts.closed[held.id]; ok {
			dropTileClosed.Inc()
			return false, false
		}
		if n := len(ts.open); n > 0 && ts.open[0].id == held.id && held.before(ts.open[n-1]) {
			// A piece that came after one the box sent later.
			dropTileOlder.Inc()
			return false, false
		}
		if len(ts.open) > 0 && ts.open[0].id != held.id {
			if held.start < ts.open[0].start {
				// A piece of an older tile than the one filling.
				dropTileClosed.Inc()
				return false, false
			}
			dropOpen = true
		}
		dropOpen = dropOpen || t.Whole()
		if !dropOpen && len(ts.open) >= cloudwire.TilePiecesMax {
			// More appends than a box sends between whole pieces. The
			// pieces held still lay back into the tile; this one waits
			// for the box's next whole piece, which carries it too.
			dropTilePieces.Inc()
			return false, false
		}
	}
	if dropOpen {
		for _, p := range ts.open {
			replaced += int64(len(p.env))
		}
	}
	if grow := int64(len(env)) - replaced; grow > 0 {
		if ts.bytes+grow > TileBytesPerHome {
			dropTileHome.Inc()
			return false, true
		}
		if x.s.tileBytes.Load()+grow > x.s.tileBytesMax {
			dropTileFull.Inc()
			return false, true
		}
	}
	if dropOpen {
		x.dropOpenLocked()
	}
	if !t.Partial {
		if old, ok := ts.closed[held.id]; ok {
			x.tileBytesLocked(-int64(len(old.env)))
		}
		if ts.closed == nil {
			ts.closed = map[string]heldTile{}
		}
		ts.closed[held.id] = held
		x.tileBytesLocked(int64(len(env)))
		// Never more than 48 hours can touch.
		for len(ts.closed) > cloudwire.TilesClosedMax {
			oldest := ""
			for id, c := range ts.closed {
				if oldest == "" || c.start < ts.closed[oldest].start {
					oldest = id
				}
			}
			x.tileBytesLocked(-int64(len(ts.closed[oldest].env)))
			delete(ts.closed, oldest)
		}
	} else {
		ts.open = append(ts.open, held)
		x.tileBytesLocked(int64(len(env)))
	}
	at := stamp()
	for sess := range x.h.sessions {
		if sess.x.mayRead(cloudwire.MsgTiles) {
			sess.deliver(env, at)
		}
	}
	return true, false
}

// TileRoom says whether a tile dropped for lack of memory would be kept now:
// the store and the home are both well under their bounds.
func (x *Handle) TileRoom() bool {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.s.tileBytes.Load() < x.s.tileBytesMax/10*9 && x.h.tiles.bytes < TileBytesPerHome/4*3
}

// HoldsTiles says whether the roster in force lets the service hold tiles.
func (x *Handle) HoldsTiles() bool {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.h.holdsTilesLocked()
}

// TilesHave is each closed tile the home holds, by id, for hello_ok.
func (x *Handle) TilesHave() map[string]string {
	have := map[string]string{}
	if x.kind != Box {
		return have
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	x.pruneTilesLocked(x.s.now().UnixMilli())
	for id, c := range x.h.tiles.closed {
		have[id] = c.etag
	}
	return have
}

// Tiles answers tiles.get: each closed tile the device lacks at its etag,
// oldest first, then every piece of the trailing tile in the order the box
// sent them, each envelope as the box signed it. A device that may not read
// tiles gets none. It answers while the box is away too: tiles are history,
// dated by the box.
func (x *Handle) Tiles(have map[string]string) ([][]byte, error) {
	if x.kind != Device {
		return nil, ErrDenied
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	if !x.mayRead(cloudwire.MsgTiles) || !x.h.holdsTilesLocked() {
		return nil, nil
	}
	x.pruneTilesLocked(x.s.now().UnixMilli())
	closed := make([]heldTile, 0, len(x.h.tiles.closed))
	for _, c := range x.h.tiles.closed {
		if have[c.id] != c.etag {
			closed = append(closed, c)
		}
	}
	sort.Slice(closed, func(a, b int) bool { return closed[a].start < closed[b].start })
	var out [][]byte
	for _, c := range closed {
		out = append(out, c.env)
	}
	for _, p := range x.h.tiles.open {
		out = append(out, p.env)
	}
	return out, nil
}

// holdsTilesLocked says whether the roster in force lets the service hold
// tiles: a copy it serves, with ftw.history.read in the grant. The caller
// holds h.mu.
func (h *home) holdsTilesLocked() bool {
	r := h.roster
	return r != nil && slices.Contains(r.Grant.Purposes, protocol.CloudPurposeServe) &&
		slices.Contains(r.Grant.Scopes, protocol.ScopeHistoryRead)
}

// pruneTilesLocked forgets the tiles that ended 48 hours or more before now.
// The caller holds h.mu.
func (x *Handle) pruneTilesLocked(now int64) { x.s.pruneTiles(x.h, now) }

func (s *Store) pruneTiles(h *home, now int64) {
	ts := &h.tiles
	for id, c := range ts.closed {
		if c.end() <= now-cloudwire.TileKeepMs {
			s.addTileBytes(h, -int64(len(c.env)))
			delete(ts.closed, id)
		}
	}
	if len(ts.open) > 0 && ts.open[0].end() <= now-cloudwire.TileKeepMs {
		s.dropOpen(h)
	}
}

// dropTiles forgets every tile of the home. The caller holds h.mu.
func (s *Store) dropTiles(h *home) {
	s.addTileBytes(h, -h.tiles.bytes)
	h.tiles = tileSet{}
}

func (x *Handle) dropOpenLocked() { x.s.dropOpen(x.h) }

func (s *Store) dropOpen(h *home) {
	for _, p := range h.tiles.open {
		s.addTileBytes(h, -int64(len(p.env)))
	}
	h.tiles.open = nil
}

func (x *Handle) tileBytesLocked(n int64) { x.s.addTileBytes(x.h, n) }

// addTileBytes counts n bytes of tiles into the home and the store. The
// caller holds h.mu.
func (s *Store) addTileBytes(h *home, n int64) {
	h.tiles.bytes += n
	s.tileBytes.Add(n)
	tileBytesHeld.Add(n)
}

// TileBytes is how many bytes of tiles the store holds, all homes.
func (s *Store) TileBytes() int64 { return s.tileBytes.Load() }

// sweepTiles drops a home's tiles past 48 hours, and all of them once the
// roster has run out: no phone may read them then, and a revoke made while
// the box was away cannot reach the service. Sweep calls it for every home,
// the box online or not. The caller holds h.mu.
func (s *Store) sweepTiles(h *home, now time.Time) {
	if r := h.roster; r == nil || now.After(h.rosterAt.Add(time.Duration(r.TTLS)*time.Second)) {
		s.dropTiles(h)
		return
	}
	s.pruneTiles(h, now.UnixMilli())
}
