package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
	"strings"
	"testing"
	"time"
)

func statsFixture(t *testing.T) (*Registry, time.Time, cloudwire.Grant) {
	t.Helper()
	r := open(t)
	if err := r.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 12, 30, 0, 0, time.UTC)
	g := cloudwire.Grant{TermsPolicy: cloudwire.CloudTermsPolicy, Controller: cloudwire.ControllerSourceful, Purposes: []string{protocol.CloudPurposeServe, protocol.CloudPurposeStats}, StatsID: bytes.Repeat([]byte{1}, 16), StatsPolicy: cloudwire.StatsPolicy, StatsSinceMs: now.Add(-25 * time.Hour).UnixMilli()}
	return r, now, g
}
func statsHome(t *testing.T, r *Registry, now time.Time, g cloudwire.Grant, home string, value int64) cloudwire.Stats {
	t.Helper()
	if err := r.Claim(home, []byte("key"), now); err != nil {
		t.Fatal(err)
	}
	if err := r.StatisticsGrant(home, g); err != nil {
		t.Fatal(err)
	}
	report := cloudwire.Stats{StatsID: g.StatsID, Policy: g.StatsPolicy, HourMS: now.Truncate(time.Hour).Add(-time.Hour).UnixMilli(), Metrics: map[string]int64{"flexible_power_w": value, "pv_generation_wh": 100}}
	if err := r.StatisticsPut(home, report, now); err != nil {
		t.Fatal(err)
	}
	return report
}
func TestStatisticsThresholdDedupUnknownAndDominance(t *testing.T) {
	r, now, g := statsFixture(t)
	for i := range 19 {
		statsHome(t, r, now, g, fmt.Sprint("home", i), 1000)
	}
	v, err := r.StatisticsView(now)
	if err != nil {
		t.Fatal(err)
	}
	if v.Installations.Value != nil || v.Metrics["flexible_power_w"].Value != nil {
		t.Fatal("small cohort exposed")
	}
	report := statsHome(t, r, now, g, "home19", 1000)
	if err := r.StatisticsPut("home19", report, now); err != nil {
		t.Fatal(err)
	}
	v, err = r.StatisticsView(now)
	if err != nil {
		t.Fatal(err)
	}
	if *v.Installations.Value != 20 || *v.Metrics["flexible_power_w"].Value != 20000 || *v.Metrics["pv_generation_wh"].Value != 2000 {
		t.Fatalf("wrong totals %+v", v)
	}
	if v.Metrics["pv_rated_w"].Value != nil {
		t.Fatal("unknown became zero")
	}
	report.Metrics["flexible_power_w"] = 100000
	if err := r.StatisticsPut("home19", report, now); err != nil {
		t.Fatal(err)
	}
	v, _ = r.StatisticsView(now)
	if v.Metrics["flexible_power_w"].State != "dominated" || v.Metrics["flexible_power_w"].Value != nil {
		t.Fatal("dominant home exposed")
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "home19") || strings.Contains(string(raw), "statsId") {
		t.Fatal("identifier exposed")
	}
}
func TestStatisticsWithdrawalPolicyRotationPurgeAndConsentWindow(t *testing.T) {
	r, now, g := statsFixture(t)
	report := statsHome(t, r, now, g, "home", 1000)
	old := g
	g.StatsPolicy = "old-policy"
	if err := r.StatisticsGrant("home", g); err != nil {
		t.Fatal(err)
	}
	if err := r.StatisticsPut("home", report, now); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours`).Scan(&n)
	if n != 0 {
		t.Fatal("withdrawn report stored")
	}
	g = old
	g.StatsSinceMs = now.UnixMilli()
	if err := r.StatisticsGrant("home", g); err != nil {
		t.Fatal(err)
	}
	_ = r.StatisticsPut("home", report, now)
	_ = r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours`).Scan(&n)
	if n != 0 {
		t.Fatal("pre-consent hour stored")
	}
	statsHome(t, r, now, old, "home", 1000)
	if err := r.Purge("home", nil, now); err != nil {
		t.Fatal(err)
	}
	_ = r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours`).Scan(&n)
	if n != 0 {
		t.Fatal("purge left household rows")
	}
}
func TestStatisticsRetention(t *testing.T) {
	r, now, g := statsFixture(t)
	statsHome(t, r, now, g, "home", 1000)
	if _, err := r.db.Exec(`UPDATE statistics_hours SET hour_ms=?`, now.AddDate(-2, 0, 0).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := r.StatisticsPrune(now); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours`).Scan(&n)
	if n != 0 {
		t.Fatal("old rows remain")
	}
}
