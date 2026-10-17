package registry

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The operator script reads a real registry made by Go, not a second schema
// invented by its own test. No Core or household is involved.
func TestStatisticsSubjectExportIsPrivateScopedAndOffline(t *testing.T) {
	r, now, g := statsFixture(t)
	home, other := strings.Repeat("a", 26), strings.Repeat("b", 26)
	report := statsHome(t, r, now, g, home, 1000)
	statsHome(t, r, now, g, other, 2000)
	var path string
	if err := r.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	request := filepath.Join(dir, "request.json")
	output := filepath.Join(dir, "export.json")
	data, _ := json.Marshal(map[string]any{"case_id": "0af8aa77-b089-4250-865a-431384d0d39c", "home": home,
		"identity_checked": true, "verified_by": "test-operator", "verified_at": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(request, data, 0600); err != nil {
		t.Fatal(err)
	}
	run := func() ([]byte, error) {
		return exec.Command("python3", "../../scripts/statistics-subject-request.py", "--database", path, "--request", request, "--output", output).CombinedOutput()
	}
	if out, err := run(); err == nil {
		t.Fatalf("export ran with the service's registry open: %s", out)
	}
	if out, err := exec.Command("python3", "../../scripts/statistics-subject-request.py", "--database", path, "--request", request, "--erase").CombinedOutput(); err == nil {
		t.Fatalf("erasure ran with Cloud open: %s", out)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("refused export left a file")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if out, err := run(); err != nil {
		t.Fatalf("offline export: %v %s", err, out)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		Home  string `json:"home"`
		Hours []struct {
			Metrics map[string]int64 `json:"metrics"`
		} `json:"hours"`
	}
	if err := json.Unmarshal(raw, &exported); err != nil || exported.Home != home || len(exported.Hours) != 1 || exported.Hours[0].Metrics["flexible_power_w"] != 1000 || strings.Contains(string(raw), other) {
		t.Fatalf("export crossed a home boundary: %v", err)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("export is not private")
	}
	if _, err := run(); err == nil {
		t.Fatal("export overwrote an existing file")
	}
	if err := os.Chmod(request, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(); err == nil {
		t.Fatal("public request accepted")
	}
	if err := os.Chmod(request, 0600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		bytes.Replace(data, []byte(`"identity_checked":true`), []byte(`"identity_checked":false`), 1),
		bytes.Replace(data, []byte(time.Now().UTC().Format("2006-01-02")), []byte("2020-01-01"), 1),
		bytes.Replace(data, []byte(`"identity_checked":true`), []byte(`"identity_checked":false,"identity_checked":true`), 1),
		bytes.Replace(data, []byte(home), []byte(`' OR 1=1 --`), 1),
	} {
		if err := os.WriteFile(request, invalid, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := exec.Command("python3", "../../scripts/statistics-subject-request.py", "--database", path, "--request", request, "--erase").CombinedOutput(); err == nil {
			t.Fatal("unverified or malformed erasure request accepted")
		}
	}
	if err := os.WriteFile(request, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("python3", "../../scripts/statistics-subject-request.py", "--database", path, "--request", request, "--erase").CombinedOutput(); err != nil {
		t.Fatalf("offline erasure: %v %s", err, out)
	}
	r, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if held, err := r.StatisticsRestricted(home); err != nil || !held {
		t.Fatal("erasure did not persist a rights hold", err)
	}
	if err := r.StatisticsGrant(home, g); err == nil {
		t.Fatal("old box restarted restricted collection")
	}
	g.StatsID = bytes.Repeat([]byte{9}, 16)
	if err := r.StatisticsGrant(home, g); err == nil {
		t.Fatal("new policy bypassed the unresolved rights request")
	}
	if err := r.StatisticsPut(home, report, now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours WHERE home=?`, home).Scan(&n); err != nil || n != 0 {
		t.Fatal("erased hours reappeared", n, err)
	}
	if err := r.rd.QueryRow(`SELECT COUNT(*) FROM statistics_hours WHERE home=?`, other).Scan(&n); err != nil || n != 1 {
		t.Fatal("another home's hours changed", n, err)
	}
}
