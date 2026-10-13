// Package registry is the service's only disk state: which homes exist, the
// box key each was claimed with, and the roster the box last signed. It holds
// no readings. Deleted rows are overwritten (secure_delete), so a purge does
// not leave a home's roster in free pages.
package registry

import (
	"database/sql"
	"errors"
	"fmt"
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
	db *sql.DB
}

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

// Open opens or creates the registry at path.
func Open(path string) (*Registry, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)&_pragma=busy_timeout(5000)")
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
);`)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("registry: schema: %w", err)
	}
	return &Registry{db: db}, nil
}

// Close closes the file.
func (r *Registry) Close() error { return r.db.Close() }

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
	err := r.db.QueryRow(`SELECT home, pk, created_ms, roster, roster_seq, roster_ms, grant_id FROM homes WHERE home = ?`, home).
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

// SetRoster keeps the signed roster envelope.
func (r *Registry) SetRoster(home string, seq uint64, grantID, envelope []byte, now time.Time) error {
	_, err := r.db.Exec(`UPDATE homes SET roster = ?, roster_seq = ?, roster_ms = ?, grant_id = ? WHERE home = ? AND roster_seq <= ?`,
		envelope, int64(seq), now.UnixMilli(), grantID, home, int64(seq))
	return err
}

// Purge deletes a home and leaves a tombstone, so the receipt can be sent
// again if the first one is lost.
func (r *Registry) Purge(home string, grantID []byte, now time.Time) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`DELETE FROM homes WHERE home = ?`, home); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO tombstones (home, grant_id, deleted_ms) VALUES (?, ?, ?)
		ON CONFLICT (home) DO NOTHING`, home, grantID, now.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// Tombstone returns a purged home's grant id and when it was deleted.
func (r *Registry) Tombstone(home string) (time.Time, bool, error) {
	var ms int64
	err := r.db.QueryRow(`SELECT deleted_ms FROM tombstones WHERE home = ?`, home).Scan(&ms)
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
	_ = r.db.QueryRow(`SELECT grant_id FROM tombstones WHERE home = ?`, home).Scan(&id)
	return id
}

// Expire deletes homes that sent no roster within NewHomeGrace, or none for
// RosterGrace, and tombstones past TombstoneKept. It returns the homes it
// deleted so memory can forget them too.
func (r *Registry) Expire(now time.Time) ([]string, error) {
	newCutoff := now.Add(-NewHomeGrace).UnixMilli()
	rosterCutoff := now.Add(-RosterGrace).UnixMilli()
	rows, err := r.db.Query(`SELECT home FROM homes
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
	}
	_, err = r.db.Exec(`DELETE FROM tombstones WHERE deleted_ms < ?`, now.Add(-TombstoneKept).UnixMilli())
	return gone, err
}
