package registry

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Extension tokens. Each row binds the SHA-256 of one token to one roster
// entry (device id and epoch) of one home; the token itself is never stored.
// A device holds one token: a new one replaces the old. A row goes when its
// home goes (the foreign key cascades on purge and expiry), when a roster
// drops the device or moves its epoch, when an owner suspends the device,
// and when it expires.

// TokenRow is one token's binding.
type TokenRow struct {
	Home     string
	DeviceID string
	Epoch    uint64
	Expires  time.Time
}

func createTokenTable(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS tokens (
	home TEXT NOT NULL REFERENCES homes(home) ON DELETE CASCADE,
	device_id TEXT NOT NULL,
	epoch INTEGER NOT NULL,
	hash BLOB NOT NULL UNIQUE,
	expires_ms INTEGER NOT NULL,
	PRIMARY KEY (home, device_id)
);`)
	return err
}

// TokenIssue binds a token's hash to a roster entry, in place of the
// device's old token.
func (r *Registry) TokenIssue(row TokenRow, hash []byte) error {
	return r.durably(func(ctx context.Context, c *sql.Conn) error {
		_, err := c.ExecContext(ctx, `INSERT INTO tokens (home, device_id, epoch, hash, expires_ms) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (home, device_id) DO UPDATE SET epoch = excluded.epoch, hash = excluded.hash,
				expires_ms = excluded.expires_ms`,
			row.Home, row.DeviceID, int64(row.Epoch), hash, row.Expires.UnixMilli())
		return err
	})
}

// TokenLookup returns the binding of a token's hash, if it has not expired.
func (r *Registry) TokenLookup(hash []byte, now time.Time) (TokenRow, bool, error) {
	var row TokenRow
	var epoch, ms int64
	err := r.rd.QueryRow(`SELECT home, device_id, epoch, expires_ms FROM tokens WHERE hash = ? AND expires_ms > ?`,
		hash, now.UnixMilli()).Scan(&row.Home, &row.DeviceID, &epoch, &ms)
	if errors.Is(err, sql.ErrNoRows) {
		return TokenRow{}, false, nil
	}
	if err != nil {
		return TokenRow{}, false, err
	}
	row.Epoch, row.Expires = uint64(epoch), time.UnixMilli(ms)
	return row, true, nil
}

// TokenDrop forgets a device's token, as when an owner suspends it.
func (r *Registry) TokenDrop(home, deviceID string) error {
	return r.durably(func(ctx context.Context, c *sql.Conn) error {
		_, err := c.ExecContext(ctx, `DELETE FROM tokens WHERE home = ? AND device_id = ?`, home, deviceID)
		return err
	})
}

// TokenDropHash forgets one token by its hash.
func (r *Registry) TokenDropHash(hash []byte) error {
	_, err := r.db.Exec(`DELETE FROM tokens WHERE hash = ?`, hash)
	return err
}

// TokenPrune keeps only the tokens whose device keep allows at its epoch, as
// a new roster says.
func (r *Registry) TokenPrune(home string, keep func(deviceID string, epoch uint64) bool) error {
	rows, err := r.rd.Query(`SELECT device_id, epoch FROM tokens WHERE home = ?`, home)
	if err != nil {
		return err
	}
	type entry struct {
		id    string
		epoch int64
	}
	var gone []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.epoch); err != nil {
			_ = rows.Close()
			return err
		}
		if !keep(e.id, uint64(e.epoch)) {
			gone = append(gone, e)
		}
	}
	_ = rows.Close()
	if len(gone) == 0 {
		return nil
	}
	// The epoch is part of the match, so a token the device got at its new
	// epoch meanwhile stays.
	return r.durably(func(ctx context.Context, c *sql.Conn) error {
		for _, e := range gone {
			if _, err := c.ExecContext(ctx, `DELETE FROM tokens WHERE home = ? AND device_id = ? AND epoch = ?`, home, e.id, e.epoch); err != nil {
				return err
			}
		}
		return nil
	})
}

// TokenExpire forgets the tokens that have expired.
func (r *Registry) TokenExpire(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM tokens WHERE expires_ms <= ?`, now.UnixMilli())
	return err
}
