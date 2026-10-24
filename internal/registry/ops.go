package registry

import (
	"database/sql"
	"errors"
	"time"
)

// OpsKept is how long the service keeps its own hours (package metrics).
const OpsKept = 90 * 24 * time.Hour

// OpsInit creates the service's own hours: one row an hour, each a sum over
// the whole service. There is no home column, and none may be added.
func (r *Registry) OpsInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS ops_hours (hour_ms INTEGER PRIMARY KEY, summary BLOB NOT NULL)`)
	return err
}

// OpsPut stores the hour that starts at hourMS as merge makes it from the
// one stored, nil if none, in one transaction, and drops hours past OpsKept.
func (r *Registry) OpsPut(hourMS int64, now time.Time, merge func(old []byte) ([]byte, error)) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	err = tx.QueryRow(`SELECT summary FROM ops_hours WHERE hour_ms = ?`, hourMS).Scan(&old)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	data, err := merge(old)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO ops_hours(hour_ms, summary) VALUES (?, ?) ON CONFLICT(hour_ms) DO UPDATE SET summary=excluded.summary`, hourMS, data); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ops_hours WHERE hour_ms < ?`, now.Add(-OpsKept).UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}

// OpsHours returns at most limit hours that start in [fromMS, toMS), oldest
// first.
func (r *Registry) OpsHours(fromMS, toMS int64, limit int) ([][]byte, error) {
	rows, err := r.rd.Query(`SELECT summary FROM ops_hours WHERE hour_ms >= ? AND hour_ms < ? ORDER BY hour_ms LIMIT ?`, fromMS, toMS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, rows.Err()
}

// OpsPrune drops hours past OpsKept, including when none is written.
func (r *Registry) OpsPrune(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM ops_hours WHERE hour_ms < ?`, now.Add(-OpsKept).UnixMilli())
	return err
}
