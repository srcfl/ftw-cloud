package registry

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Statistics tables contain only separately consented, closed-hour values.
// They have no staff read route, and leave with the home's purge.
func (r *Registry) StatisticsInit() error {
	_, err := r.db.Exec(`CREATE TABLE IF NOT EXISTS statistics_grants (
	 home TEXT PRIMARY KEY REFERENCES homes(home) ON DELETE CASCADE,
	 stats_id BLOB NOT NULL, since_ms INTEGER NOT NULL);
	 CREATE TABLE IF NOT EXISTS statistics_hours (
	 home TEXT NOT NULL REFERENCES homes(home) ON DELETE CASCADE,
	 hour_ms INTEGER NOT NULL, metrics BLOB NOT NULL, PRIMARY KEY(home,hour_ms));
	 CREATE INDEX IF NOT EXISTS statistics_hours_time ON statistics_hours(hour_ms);`)
	return err
}

// StatisticsGrant clears old consent rows before a changed grant may send.
func (r *Registry) StatisticsGrant(home string, g cloudwire.Grant) error {
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	err = tx.QueryRow(`SELECT stats_id FROM statistics_grants WHERE home=?`, home).Scan(&old)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	on := g.Controller == cloudwire.ControllerSourceful && g.StatsPolicy == cloudwire.StatsPolicy &&
		len(g.StatsID) == 16 && g.StatsSinceMs > 0 && slices.Contains(g.Purposes, protocol.CloudPurposeStats) &&
		slices.Contains(g.Purposes, protocol.CloudPurposeServe)
	if !on || !bytes.Equal(old, g.StatsID) {
		if _, err := tx.Exec(`DELETE FROM statistics_hours WHERE home=?`, home); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM statistics_grants WHERE home=?`, home); err != nil {
			return err
		}
	}
	if on {
		if _, err := tx.Exec(`INSERT INTO statistics_grants(home,stats_id,since_ms) VALUES(?,?,?)
		 ON CONFLICT(home) DO UPDATE SET stats_id=excluded.stats_id,since_ms=excluded.since_ms`, home, g.StatsID, g.StatsSinceMs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *Registry) StatisticsPut(home string, report cloudwire.Stats, now time.Time) error {
	if !report.Valid(now.UnixMilli()) {
		return errors.New("statistics: invalid closed hour")
	}
	data, err := json.Marshal(report.Metrics)
	if err != nil {
		return err
	}
	// Consent and the write are one SQL statement: a withdrawn grant cannot
	// race a pending report back into storage. Reconnects replace one hour.
	_, err = r.db.Exec(`INSERT INTO statistics_hours(home,hour_ms,metrics)
	 SELECT home,?,? FROM statistics_grants WHERE home=? AND stats_id=? AND since_ms<=?
	 ON CONFLICT(home,hour_ms) DO UPDATE SET metrics=excluded.metrics`, report.HourMS, data, home, report.StatsID, report.HourMS)
	return err
}

func (r *Registry) StatisticsPrune(now time.Time) error {
	_, err := r.db.Exec(`DELETE FROM statistics_hours WHERE hour_ms<?`, now.UTC().AddDate(0, -13, 0).UnixMilli())
	return err
}

type StatisticsCell struct {
	State string `json:"state"`
	Value *int64 `json:"value"`
	Homes *int   `json:"homes"`
}

type StatisticsView struct {
	Schema        string                    `json:"schema"`
	ObservedAt    string                    `json:"observed_at"`
	WindowStart   string                    `json:"window_start"`
	WindowEnd     string                    `json:"window_end"`
	Minimum       int                       `json:"minimum"`
	Installations StatisticsCell            `json:"installations"`
	Metrics       map[string]StatisticsCell `json:"metrics"`
}

func cell(values []int64) StatisticsCell {
	c := StatisticsCell{State: "withheld"}
	if len(values) < cloudwire.StatsMinimumHomes {
		return c
	}
	n := len(values)
	c.Homes = &n
	var sum, biggest int64
	for _, value := range values {
		sum += value
		biggest = max(biggest, value)
	}
	if sum > 0 && biggest*10 > sum*3 {
		c.State = "dominated"
		return c
	}
	c.State, c.Value = "visible", &sum
	return c
}

// StatisticsView returns cells only. Neither the home nor statsId leaves it.
// Capacities use each home's latest report; energy sums its recorded hours.
func (r *Registry) StatisticsView(now time.Time) (StatisticsView, error) {
	end := now.UTC().Truncate(time.Hour)
	start := end.Add(-24 * time.Hour)
	v := StatisticsView{Schema: "ftw.project-usage/1", ObservedAt: now.UTC().Format(time.RFC3339),
		WindowStart: start.Format(time.RFC3339), WindowEnd: end.Format(time.RFC3339), Minimum: cloudwire.StatsMinimumHomes, Metrics: map[string]StatisticsCell{}}
	rows, err := r.rd.Query(`SELECT h.home,h.hour_ms,h.metrics FROM statistics_hours h
	 JOIN statistics_grants g ON g.home=h.home WHERE h.hour_ms>=? AND h.hour_ms<? ORDER BY h.hour_ms DESC`, start.UnixMilli(), end.UnixMilli())
	if err != nil {
		return v, err
	}
	defer rows.Close()
	homes := map[string]map[string]int64{}
	for rows.Next() {
		var home string
		var hour int64
		var raw []byte
		if err := rows.Scan(&home, &hour, &raw); err != nil {
			return v, err
		}
		var metrics map[string]int64
		if err := json.Unmarshal(raw, &metrics); err != nil {
			return v, err
		}
		first := homes[home] == nil
		if first {
			homes[home] = map[string]int64{}
		}
		for key, value := range metrics {
			if key == "battery_capacity_wh" || key == "flexible_power_w" || key == "pv_rated_w" {
				if first {
					homes[home][key] = value
				}
			} else {
				homes[home][key] += value
			}
		}
	}
	if err := rows.Err(); err != nil {
		return v, err
	}
	n := len(homes)
	v.Installations = StatisticsCell{State: "withheld"}
	if n == 0 {
		zero := int64(0)
		v.Installations = StatisticsCell{State: "empty", Value: &zero}
	}
	if n >= cloudwire.StatsMinimumHomes {
		value := int64(n)
		v.Installations = StatisticsCell{State: "visible", Value: &value, Homes: &n}
	}
	for _, key := range cloudwire.StatsMetricKeys {
		values := []int64{}
		for _, metrics := range homes {
			if value, ok := metrics[key]; ok {
				values = append(values, value)
			}
		}
		v.Metrics[key] = cell(values)
	}
	return v, nil
}
