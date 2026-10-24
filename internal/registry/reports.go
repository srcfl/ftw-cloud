package registry

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/srcfl/ftw/go/protocol/energywire"
	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

// ReportIDDays is how long a report's id is kept: the day it was sent and
// the next, when the gateway still takes it, and one more.
const ReportIDDays = 3

// ReportsInit creates the ids of the reports the gateway counted: a hash of
// each report's random id under the day the box sent it, so a replay or a
// retry counts once (RFC 9458, section 6.5). The table has no time, row id
// or arrival order: it is keyed by the hash.
func (r *Registry) ReportsInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS report_ids (
		day TEXT NOT NULL,
		id BLOB NOT NULL,
		PRIMARY KEY (day, id)) WITHOUT ROWID`)
	return err
}

// FleetPutOnce adds a fleet report to today's counters unless its id was
// counted already.
func (r *Registry) FleetPutOnce(day string, id []byte, report fleetwire.Report, now time.Time) (added, repeat bool, err error) {
	return r.once(day, id, func(tx *sql.Tx) (bool, error) { return fleetPutTx(tx, report, now) })
}

// EnergyAddOnce adds an energy report to its date's totals unless its id was
// counted already.
func (r *Registry) EnergyAddOnce(day string, id []byte, rep energywire.Report) (added, repeat bool, err error) {
	return r.once(day, id, func(tx *sql.Tx) (bool, error) { return energyAdd(tx, rep) })
}

// once records the id and runs add in one transaction. A repeat runs nothing.
// When add refuses (a full day), the id is not kept either.
func (r *Registry) once(day string, id []byte, add func(*sql.Tx) (bool, error)) (added, repeat bool, err error) {
	sum := sha256.Sum256(id)
	tx, err := r.db.Begin()
	if err != nil {
		return false, false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO report_ids(day, id) VALUES (?, ?) ON CONFLICT DO NOTHING`, day, sum[:16])
	if err != nil {
		return false, false, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return false, err == nil, err
	}
	if added, err = add(tx); err != nil || !added {
		return false, false, err
	}
	return true, false, tx.Commit()
}

// ReportSeen reports whether a report's id was counted already, without
// recording it, so a repeat can be answered before any budget is spent.
func (r *Registry) ReportSeen(day string, id []byte) (bool, error) {
	sum := sha256.Sum256(id)
	var one int
	err := r.rd.QueryRow(`SELECT 1 FROM report_ids WHERE day = ? AND id = ?`, day, sum[:16]).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ReportsPrune drops ids older than ReportIDDays.
func (r *Registry) ReportsPrune(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM report_ids WHERE day < ?`, now.UTC().AddDate(0, 0, 1-ReportIDDays).Format(time.DateOnly))
	return err
}
