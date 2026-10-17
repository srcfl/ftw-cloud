package registry

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/srcfl/ftw/go/protocol/fleetwire"
)

// FleetInit creates only daily totals. No report or address goes on disk.
func (r *Registry) FleetInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS fleet_days (date TEXT PRIMARY KEY, totals BLOB NOT NULL)`)
	return err
}

// FleetPut reduces a report into today's counters in one transaction.
func (r *Registry) FleetPut(report fleetwire.Report, now time.Time) (bool, error) {
	tx, err := r.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	date := now.UTC().Format(time.DateOnly)
	day := fleetwire.NewDay(date)
	var old []byte
	err = tx.QueryRow(`SELECT totals FROM fleet_days WHERE date = ?`, date).Scan(&old)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if len(old) > 0 {
		if err := json.Unmarshal(old, &day); err != nil {
			return false, err
		}
	}
	if !day.Add(report) {
		return false, nil
	}
	data, err := json.Marshal(day)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(`INSERT INTO fleet_days(date, totals) VALUES (?, ?) ON CONFLICT(date) DO UPDATE SET totals=excluded.totals`, date, data); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`DELETE FROM fleet_days WHERE date < ? OR date NOT IN (SELECT date FROM fleet_days ORDER BY date DESC LIMIT ?)`, now.UTC().AddDate(0, 0, 1-fleetwire.MaxDays).Format(time.DateOnly), fleetwire.MaxDays); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

func (r *Registry) FleetView(now time.Time) (fleetwire.View, error) {
	view := fleetwire.View{Schema: fleetwire.StatsSchema, Meaning: fleetwire.Meaning, Days: []fleetwire.Day{}}
	rows, err := r.rd.Query(`SELECT totals FROM fleet_days WHERE date >= ? AND date <= ? ORDER BY date DESC LIMIT ?`, now.UTC().AddDate(0, 0, 1-fleetwire.MaxDays).Format(time.DateOnly), now.UTC().Format(time.DateOnly), fleetwire.MaxDays)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		var day fleetwire.Day
		if err := rows.Scan(&data); err != nil {
			return view, err
		}
		if err := json.Unmarshal(data, &day); err != nil {
			return view, err
		}
		view.Days = append(view.Days, day)
	}
	return view, rows.Err()
}

// FleetPrune expires dates by calendar age, including when no reports arrive.
func (r *Registry) FleetPrune(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM fleet_days WHERE date < ?`, now.UTC().AddDate(0, 0, 1-fleetwire.MaxDays).Format(time.DateOnly))
	return err
}
