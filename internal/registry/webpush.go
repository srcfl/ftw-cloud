package registry

import (
	"database/sql"
	"encoding/json"
	"errors"
)

// Browser notices live in the signed roster. This table holds only which
// notices went in the current outage, so an exit does not send them twice.
func (r *Registry) WebPushInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS webpush_sent (home TEXT PRIMARY KEY REFERENCES homes(home) ON DELETE CASCADE, due_ms INTEGER NOT NULL, ids BLOB NOT NULL)`)
	return err
}

// WebPushOutage is zero once the box is back. It is stable across a restart.
func (r *Registry) WebPushOutage(home string) (int64, error) {
	var due int64
	err := r.rd.QueryRow(`SELECT due_ms FROM away WHERE home=?`, home).Scan(&due)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return due, err
}

func (r *Registry) WebPushSent(home string, due int64) ([]string, error) {
	var raw []byte
	err := r.rd.QueryRow(`SELECT ids FROM webpush_sent WHERE home=? AND due_ms=?`, home, due).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	err = json.Unmarshal(raw, &ids)
	return ids, err
}

func (r *Registry) WebPushMark(home string, due int64, id string) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRow(`SELECT ids FROM webpush_sent WHERE home=? AND due_ms=?`, home, due).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var ids []string
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &ids); err != nil {
			return err
		}
	}
	for _, old := range ids {
		if old == id {
			return nil
		}
	}
	ids = append(ids, id)
	raw, err = json.Marshal(ids)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO webpush_sent(home,due_ms,ids) SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM away WHERE home=? AND due_ms=?) ON CONFLICT(home) DO UPDATE SET due_ms=excluded.due_ms,ids=excluded.ids`, home, due, raw, home, due)
	if err != nil {
		return err
	}
	return tx.Commit()
}
