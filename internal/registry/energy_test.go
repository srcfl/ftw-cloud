package registry

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol/energywire"
)

// Reports leave one row per date, a count and six sums, and nothing that
// was in any one of them.
func TestEnergyKeepsOnlyDailyTotals(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.EnergyInit(); err != nil {
		t.Fatal(err)
	}
	rep := energywire.Report{Schema: energywire.Schema, Date: "2026-10-23", PVGeneration: 7, GridImport: 1}
	for i := range 10 {
		rep.Date = []string{"2026-10-22", "2026-10-23"}[i%2]
		if ok, err := r.EnergyAdd(rep); err != nil || !ok {
			t.Fatal(err)
		}
	}
	var rows, columns int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM energy_days`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("rows %d %v", rows, err)
	}
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('energy_days')`).Scan(&columns); err != nil || columns != 2+2*len(energywire.Fields) {
		t.Fatalf("columns %d %v", columns, err)
	}
	totals, err := r.EnergyTotals("2026-10-22", "2026-10-23")
	if d := totals["2026-10-23"]; err != nil || d.Reports != 5 || d.Sums[0] != 35 || d.Sums[1] != 5 || d.Had != [6]int64{5, 5, 0, 0, 0, 0} {
		t.Fatalf("%+v %v", d, err)
	}

	// A full date takes no more.
	if _, err := r.db.Exec(`UPDATE energy_days SET reports = ? WHERE date = '2026-10-23'`, energywire.MaxReports); err != nil {
		t.Fatal(err)
	}
	if ok, err := r.EnergyAdd(rep); err != nil || ok {
		t.Fatalf("a full date took a report: %v", err)
	}

	// Dates expire by age, even when no report arrives.
	if err := r.EnergyPrune(time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	totals, _ = r.EnergyTotals("2026-10-01", "2026-10-31")
	if _, ok := totals["2026-10-22"]; ok || len(totals) != 1 {
		t.Fatalf("after pruning %v", totals)
	}
}
