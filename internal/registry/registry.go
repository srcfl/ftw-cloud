// Package registry is the service's only disk state: which homes exist, the
// box key each was claimed with, the roster the box last signed, owners'
// suspensions, APNs registrations and the hashes of extension tokens. It
// holds no readings. Deleted rows are overwritten (secure_delete), so a purge does
// not leave a home's roster in free pages.
package registry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Retention, from the protocol's "Numbers in one place".
const (
	// NewHomeGrace is how long a new home may go without a roster.
	NewHomeGrace = 24 * time.Hour
	// RosterGrace is how long a home lives without a valid roster.
	RosterGrace = 90 * 24 * time.Hour
	// TombstoneKept is how long a purged home's receipt can be asked for
	// again.
	TombstoneKept = 90 * 24 * time.Hour
)

// Registry is the SQLite file.
type Registry struct {
	// db is the one connection that writes; rd is a few that only read.
	// The file is in WAL mode, so readers never wait for the writer, and
	// a box's reconnect or a token read does not queue behind a write.
	db *sql.DB
	rd *sql.DB

	// suspended mirrors the suspensions table, so admission, which runs
	// under a home's lock, never waits for SQLite. Every write updates it
	// after the file.
	susMu     sync.Mutex
	suspended map[suspendKey]uint64
}

type suspendKey struct{ home, device string }

// Home is one registered home.
type Home struct {
	ID        string
	PK        []byte
	CreatedAt time.Time
	// Roster is the roster envelope exactly as the box signed it, nil when
	// none has arrived; RosterSeq its number and RosterAt when it arrived.
	Roster    []byte
	RosterSeq uint64
	RosterAt  time.Time
	GrantID   []byte
}

// readers is how many connections may read at once.
const readers = 4

// Open opens or creates the registry at path.
//
// synchronous(NORMAL) syncs the file at each checkpoint rather than at each
// commit. A power cut can lose the last commits but never corrupts the file.
// What that loses comes back by itself: a box sends its roster again at its
// next connect, and a phone registers again at its next start. A reconnect
// storm is then a matter of memory, not of disk syncs. The writes that
// narrow access, and would widen it again if lost, go through durably.
func Open(path string) (*Registry, error) {
	const pragmas = "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", "file:"+path+"?"+pragmas+"&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS homes (
	home TEXT PRIMARY KEY,
	pk BLOB NOT NULL,
	created_ms INTEGER NOT NULL,
	roster BLOB,
	roster_seq INTEGER NOT NULL DEFAULT 0,
	roster_ms INTEGER NOT NULL DEFAULT 0,
	grant_id BLOB
);
CREATE TABLE IF NOT EXISTS tombstones (
	home TEXT PRIMARY KEY,
	grant_id BLOB,
	deleted_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS suspensions (
	home TEXT NOT NULL,
	device_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	since_ms INTEGER NOT NULL,
	PRIMARY KEY (home, device_id)
);
CREATE TABLE IF NOT EXISTS away (
	home TEXT PRIMARY KEY REFERENCES homes(home) ON DELETE CASCADE,
	due_ms INTEGER NOT NULL,
	told INTEGER NOT NULL DEFAULT 0
);`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("registry: schema: %w", err)
	}
	if err := createPushTable(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("registry: schema: %w", err)
	}
	if err := createTokenTable(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("registry: schema: %w", err)
	}
	rd, err := sql.Open("sqlite", "file:"+path+"?"+pragmas+"&_pragma=query_only(1)")
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	rd.SetMaxOpenConns(readers)
	r := &Registry{db: db, rd: rd, suspended: map[suspendKey]uint64{}}
	if err := r.loadSuspensions(); err != nil {
		_ = r.Close()
		return nil, fmt.Errorf("registry: suspensions: %w", err)
	}
	return r, nil
}

func (r *Registry) loadSuspensions() error {
	rows, err := r.db.Query(`SELECT home, device_id, epoch FROM suspensions`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k suspendKey
		var epoch int64
		if err := rows.Scan(&k.home, &k.device, &epoch); err != nil {
			return err
		}
		r.suspended[k] = uint64(epoch)
	}
	return rows.Err()
}

// forgetSuspensions drops a home's suspensions from memory, after the file.
func (r *Registry) forgetSuspensions(home string) {
	r.susMu.Lock()
	defer r.susMu.Unlock()
	for k := range r.suspended {
		if k.home == home {
			delete(r.suspended, k)
		}
	}
}

// durably runs f on the one writing connection with each commit synced to
// disk, as synchronous(FULL) does: an owner's suspension, a purge, a token
// dropped or pruned, and a roster with a higher number, which may remove a
// device. A power cut must not undo any of them.
func (r *Registry) durably(f func(ctx context.Context, c *sql.Conn) error) error {
	ctx := context.Background()
	c, err := r.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, `PRAGMA synchronous = FULL`); err != nil {
		return err
	}
	defer func() { _, _ = c.ExecContext(ctx, `PRAGMA synchronous = NORMAL`) }()
	return f(ctx, c)
}

// Close closes the file.
func (r *Registry) Close() error {
	rdErr := r.rd.Close()
	if err := r.db.Close(); err != nil {
		return err
	}
	return rdErr
}

// Claim registers a home at its box's first hello. A home id is a hash of the
// key, so a second claim with another key is impossible by construction, and
// one with the same key is a no-op. A purged home is not claimed again.
func (r *Registry) Claim(home string, pk []byte, now time.Time) error {
	if _, ok, err := r.Tombstone(home); err != nil || ok {
		if ok {
			return ErrPurged
		}
		return err
	}
	// A box that reconnects finds its row and writes nothing.
	var known int
	if err := r.rd.QueryRow(`SELECT COUNT(*) FROM homes WHERE home = ?`, home).Scan(&known); err != nil {
		return err
	}
	if known > 0 {
		return nil
	}
	_, err := r.db.Exec(`INSERT INTO homes (home, pk, created_ms) VALUES (?, ?, ?) ON CONFLICT (home) DO NOTHING`,
		home, pk, now.UnixMilli())
	return err
}

// ErrPurged is a home whose box asked for it to be deleted.
var ErrPurged = errors.New("registry: home was purged")

// Get returns one home.
func (r *Registry) Get(home string) (Home, bool, error) {
	var h Home
	var created, rosterMs int64
	var seq int64
	err := r.rd.QueryRow(`SELECT home, pk, created_ms, roster, roster_seq, roster_ms, grant_id FROM homes WHERE home = ?`, home).
		Scan(&h.ID, &h.PK, &created, &h.Roster, &seq, &rosterMs, &h.GrantID)
	if errors.Is(err, sql.ErrNoRows) {
		return Home{}, false, nil
	}
	if err != nil {
		return Home{}, false, err
	}
	h.CreatedAt, h.RosterSeq = time.UnixMilli(created), uint64(seq)
	if rosterMs > 0 {
		h.RosterAt = time.UnixMilli(rosterMs)
	}
	return h, true, nil
}

// Rosters returns every home that holds a signed roster, for the service to
// admit phones by again after a restart. It is upkeep at start, never a
// request.
func (r *Registry) Rosters() ([]Home, error) {
	rows, err := r.rd.Query(`SELECT home, pk, created_ms, roster, roster_seq, roster_ms, grant_id FROM homes WHERE roster IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Home
	for rows.Next() {
		var h Home
		var created, seq, rosterMs int64
		if err := rows.Scan(&h.ID, &h.PK, &created, &h.Roster, &seq, &rosterMs, &h.GrantID); err != nil {
			return nil, err
		}
		h.CreatedAt, h.RosterSeq, h.RosterAt = time.UnixMilli(created), uint64(seq), time.UnixMilli(rosterMs)
		out = append(out, h)
	}
	return out, rows.Err()
}

// Away is a home whose box is gone, as the dead man's switch keeps it across
// a restart: when box.unreachable is due, and whether it went.
type Away struct {
	Home string
	Due  time.Time
	Told bool
}

// AwaySet records that a home's box went and when box.unreachable is due.
func (r *Registry) AwaySet(home string, due time.Time) error {
	_, err := r.db.Exec(`INSERT INTO away (home, due_ms, told) SELECT ?, ?, 0 WHERE EXISTS (SELECT 1 FROM homes WHERE home = ?)
		ON CONFLICT (home) DO UPDATE SET due_ms = excluded.due_ms, told = 0`, home, due.UnixMilli(), home)
	return err
}

// AwayTold records that box.unreachable went.
func (r *Registry) AwayTold(home string) error {
	_, err := r.db.Exec(`UPDATE away SET told = 1 WHERE home = ?`, home)
	return err
}

// AwayClear forgets a home's absence: its box is back, or the home is gone.
func (r *Registry) AwayClear(home string) error {
	_, err := r.db.Exec(`DELETE FROM away WHERE home = ?`, home)
	return err
}

// AwayAll returns every home recorded as away.
func (r *Registry) AwayAll() ([]Away, error) {
	rows, err := r.rd.Query(`SELECT home, due_ms, told FROM away`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Away
	for rows.Next() {
		var a Away
		var due int64
		if err := rows.Scan(&a.Home, &due, &a.Told); err != nil {
			return nil, err
		}
		a.Due = time.UnixMilli(due)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetRoster keeps the signed roster envelope.
func (r *Registry) SetRoster(home string, seq uint64, grantID, envelope []byte, now time.Time) error {
	const q = `UPDATE homes SET roster = ?, roster_seq = ?, roster_ms = ?, grant_id = ? WHERE home = ? AND roster_seq <= ?`
	args := []any{envelope, int64(seq), now.UnixMilli(), grantID, home, int64(seq)}
	// The same number renews the time to live and can wait for the next
	// checkpoint; a higher one may remove a device, so it is synced.
	var held int64
	if err := r.rd.QueryRow(`SELECT roster_seq FROM homes WHERE home = ?`, home).Scan(&held); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if int64(seq) <= held {
		_, err := r.db.Exec(q, args...)
		return err
	}
	return r.durably(func(ctx context.Context, c *sql.Conn) error {
		_, err := c.ExecContext(ctx, q, args...)
		return err
	})
}

// Purge deletes a home and leaves a tombstone, so the receipt can be sent
// again if the first one is lost.
func (r *Registry) Purge(home string, grantID []byte, now time.Time) error {
	err := r.durably(func(ctx context.Context, c *sql.Conn) error {
		tx, err := c.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`DELETE FROM homes WHERE home = ?`, home); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM suspensions WHERE home = ?`, home); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO tombstones (home, grant_id, deleted_ms) VALUES (?, ?, ?)
			ON CONFLICT (home) DO NOTHING`, home, grantID, now.UnixMilli()); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err != nil {
		return err
	}
	r.forgetSuspensions(home)
	return nil
}

// Tombstone returns a purged home's grant id and when it was deleted.
func (r *Registry) Tombstone(home string) (time.Time, bool, error) {
	var ms int64
	err := r.rd.QueryRow(`SELECT deleted_ms FROM tombstones WHERE home = ?`, home).Scan(&ms)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(ms), true, nil
}

// TombstoneGrant returns the grant id a purged home was deleted under.
func (r *Registry) TombstoneGrant(home string) []byte {
	var id []byte
	_ = r.rd.QueryRow(`SELECT grant_id FROM tombstones WHERE home = ?`, home).Scan(&id)
	return id
}

// Expire deletes homes that sent no roster within NewHomeGrace, or none for
// RosterGrace, and tombstones past TombstoneKept. It returns the homes it
// deleted so memory can forget them too.
func (r *Registry) Expire(now time.Time) ([]string, error) {
	newCutoff := now.Add(-NewHomeGrace).UnixMilli()
	rosterCutoff := now.Add(-RosterGrace).UnixMilli()
	rows, err := r.rd.Query(`SELECT home FROM homes
		WHERE (roster_ms = 0 AND created_ms < ?) OR (roster_ms > 0 AND roster_ms < ?)`, newCutoff, rosterCutoff)
	if err != nil {
		return nil, err
	}
	var gone []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			_ = rows.Close()
			return nil, err
		}
		gone = append(gone, h)
	}
	_ = rows.Close()
	for _, h := range gone {
		if _, err := r.db.Exec(`DELETE FROM homes WHERE home = ?`, h); err != nil {
			return nil, err
		}
		if _, err := r.db.Exec(`DELETE FROM suspensions WHERE home = ?`, h); err != nil {
			return nil, err
		}
		r.forgetSuspensions(h)
	}
	_, err = r.db.Exec(`DELETE FROM tombstones WHERE deleted_ms < ?`, now.Add(-TombstoneKept).UnixMilli())
	return gone, err
}

// Suspend records an owner's suspension of one roster device at its current
// epoch. It only narrows access: the device must already be in the roster,
// which the caller checks, and the suspension ends when the roster drops the
// device or its epoch changes.
func (r *Registry) Suspend(home, deviceID string, epoch uint64, now time.Time) error {
	// Memory first: a suspension narrows, so it bites before the write
	// is done, and a write that fails leaves it biting until a restart.
	r.susMu.Lock()
	r.suspended[suspendKey{home, deviceID}] = epoch
	r.susMu.Unlock()
	return r.durably(func(ctx context.Context, c *sql.Conn) error {
		_, err := c.ExecContext(ctx, `INSERT INTO suspensions (home, device_id, epoch, since_ms) VALUES (?, ?, ?, ?)
			ON CONFLICT (home, device_id) DO UPDATE SET epoch = excluded.epoch, since_ms = excluded.since_ms`,
			home, deviceID, int64(epoch), now.UnixMilli())
		return err
	})
}

// Unsuspend lifts a suspension.
func (r *Registry) Unsuspend(home, deviceID string) error {
	if _, err := r.db.Exec(`DELETE FROM suspensions WHERE home = ? AND device_id = ?`, home, deviceID); err != nil {
		return err
	}
	r.susMu.Lock()
	delete(r.suspended, suspendKey{home, deviceID})
	r.susMu.Unlock()
	return nil
}

// Suspended reports whether a device is suspended at this epoch. It reads
// memory, never the file, so admission under a home's lock never waits.
func (r *Registry) Suspended(home, deviceID string, epoch uint64) bool {
	r.susMu.Lock()
	defer r.susMu.Unlock()
	held, ok := r.suspended[suspendKey{home, deviceID}]
	return ok && held == epoch
}

// PruneSuspensions drops the suspensions a new roster ended: devices it no
// longer lists, and devices whose epoch moved.
func (r *Registry) PruneSuspensions(home string, epochs map[string]uint64) error {
	rows, err := r.rd.Query(`SELECT device_id, epoch FROM suspensions WHERE home = ?`, home)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var id string
		var epoch int64
		if err := rows.Scan(&id, &epoch); err != nil {
			_ = rows.Close()
			return err
		}
		if e, ok := epochs[id]; !ok || e != uint64(epoch) {
			gone = append(gone, id)
		}
	}
	_ = rows.Close()
	for _, id := range gone {
		if err := r.Unsuspend(home, id); err != nil {
			return err
		}
	}
	return nil
}
