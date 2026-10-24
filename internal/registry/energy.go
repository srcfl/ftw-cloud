package registry

import (
	"time"

	"github.com/srcfl/ftw/go/protocol/energywire"
)

// EnergyDays is how long a date's energy totals are kept.
const EnergyDays = 30

// EnergyInit creates only daily totals: one row per date, a count and six
// sums. No report, address or time of arrival goes on disk.
func (r *Registry) EnergyInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS energy_days (
		date TEXT PRIMARY KEY,
		reports INTEGER NOT NULL,
		pv_generation_kwh INTEGER NOT NULL,
		grid_import_kwh INTEGER NOT NULL,
		grid_export_kwh INTEGER NOT NULL,
		battery_charge_kwh INTEGER NOT NULL,
		battery_discharge_kwh INTEGER NOT NULL,
		vehicle_charge_kwh INTEGER NOT NULL)`)
	return err
}

// EnergyAdd adds one report to its date's totals in one statement. False
// means the date already holds energywire.MaxReports.
func (r *Registry) EnergyAdd(rep energywire.Report) (bool, error) {
	s := rep.Sums()
	res, err := r.db.Exec(`INSERT INTO energy_days VALUES (?, 1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(date) DO UPDATE SET reports = reports + 1,
			pv_generation_kwh = pv_generation_kwh + excluded.pv_generation_kwh,
			grid_import_kwh = grid_import_kwh + excluded.grid_import_kwh,
			grid_export_kwh = grid_export_kwh + excluded.grid_export_kwh,
			battery_charge_kwh = battery_charge_kwh + excluded.battery_charge_kwh,
			battery_discharge_kwh = battery_discharge_kwh + excluded.battery_discharge_kwh,
			vehicle_charge_kwh = vehicle_charge_kwh + excluded.vehicle_charge_kwh
		WHERE reports < ?`,
		rep.Date, s[0], s[1], s[2], s[3], s[4], s[5], energywire.MaxReports)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// EnergyDay is one date's totals, sums in energywire.Fields order.
type EnergyDay struct {
	Date    string
	Reports int64
	Sums    [6]int64
}

// EnergyTotals reads the dates from first to last, both included.
func (r *Registry) EnergyTotals(first, last string) (map[string]EnergyDay, error) {
	rows, err := r.rd.Query(`SELECT date, reports, pv_generation_kwh, grid_import_kwh, grid_export_kwh,
		battery_charge_kwh, battery_discharge_kwh, vehicle_charge_kwh
		FROM energy_days WHERE date >= ? AND date <= ? LIMIT ?`, first, last, EnergyDays+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]EnergyDay{}
	for rows.Next() {
		var d EnergyDay
		if err := rows.Scan(&d.Date, &d.Reports, &d.Sums[0], &d.Sums[1], &d.Sums[2], &d.Sums[3], &d.Sums[4], &d.Sums[5]); err != nil {
			return nil, err
		}
		out[d.Date] = d
	}
	return out, rows.Err()
}

// EnergyPrune drops dates older than EnergyDays, even when no report comes.
func (r *Registry) EnergyPrune(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM energy_days WHERE date < ?`, now.UTC().AddDate(0, 0, -EnergyDays).Format(time.DateOnly))
	return err
}
