package shard

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const homeA = "fjzyr67buzpyncqmjliwgezvde"

func TestOneShardHoldsEveryHome(t *testing.T) {
	d := Single("cloud.ftw.energy")
	for _, home := range []string{homeA, "aaaaaaaaaaaaaaaaaaaaaaaaaa", "zzzzzzzzzzzzzzzzzzzzzzzzzz"} {
		if host, ours := d.Owner(home); !ours || host != "cloud.ftw.energy" {
			t.Fatalf("Owner(%s) = %s, %v", home, host, ours)
		}
	}
	if d.Shards() != 1 || d.Host() != "cloud.ftw.energy" {
		t.Fatal(d.Shards(), d.Host())
	}
}

func TestBucketsAndMovedHomesNameTheirShard(t *testing.T) {
	b := Bucket(homeA)
	f := File{Self: "s1", Default: "s1",
		Shards:  map[string]string{"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
		Buckets: map[string][]string{"s2": {itoa(b)}}}
	d, err := f.Directory()
	if err != nil {
		t.Fatal(err)
	}
	if host, ours := d.Owner(homeA); ours || host != "s2.cloud.ftw.energy" {
		t.Fatalf("a home in s2's bucket: %s, %v", host, ours)
	}
	// Moved back on its own, it is s1's again.
	f.Homes = map[string]string{homeA: "s1"}
	if d, err = f.Directory(); err != nil {
		t.Fatal(err)
	}
	if !d.Ours(homeA) {
		t.Fatal("a moved home is not where the directory says")
	}
	// The same file on s2 is the mirror image.
	f.Self, f.Homes = "s2", nil
	if d, err = f.Directory(); err != nil {
		t.Fatal(err)
	}
	if !d.Ours(homeA) {
		t.Fatal("s2 does not hold its own bucket")
	}
}

// Buckets spread homes evenly enough that moving half of them moves about
// half the homes.
func TestBucketsSpreadHomes(t *testing.T) {
	counts := make([]int, Buckets)
	alphabet := "abcdefghijklmnopqrstuvwxyz234567"
	for i := range 64 * Buckets {
		var b strings.Builder
		for j := range 26 {
			b.WriteByte(alphabet[(i*7+j*13+i/32*j)%32])
		}
		counts[Bucket(b.String())]++
	}
	upper := 0
	for i := Buckets / 2; i < Buckets; i++ {
		upper += counts[i]
	}
	if share := float64(upper) / float64(64*Buckets); share < 0.45 || share > 0.55 {
		t.Fatalf("the upper half of the buckets holds %.2f of the homes", share)
	}
}

func TestADirectoryThatCouldSendAClientAwayIsRefused(t *testing.T) {
	good := func() File {
		return File{Self: "s1", Default: "s1",
			Shards: map[string]string{"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"}}
	}
	for name, change := range map[string]func(*File){
		"a host off the domain": func(f *File) { f.Shards["s2"] = "evil.example" },
		"two labels deep":       func(f *File) { f.Shards["s2"] = "a.b.cloud.ftw.energy" },
		"no default":            func(f *File) { f.Default = "s9" },
		"self unknown":          func(f *File) { f.Self = "s9" },
		"buckets for nobody":    func(f *File) { f.Buckets = map[string][]string{"s9": {"1"}} },
		"bucket out of range":   func(f *File) { f.Buckets = map[string][]string{"s2": {"200-256"}} },
		"bucket twice": func(f *File) {
			f.Shards["s3"] = "s3.cloud.ftw.energy"
			f.Buckets = map[string][]string{"s2": {"0-10"}, "s3": {"10"}}
		},
		"a home id that is not one": func(f *File) { f.Homes = map[string]string{"x": "s2"} },
		"a home for nobody":         func(f *File) { f.Homes = map[string]string{homeA: "s9"} },
	} {
		f := good()
		change(&f)
		if _, err := f.Directory(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := good().Directory(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadReadsTheFileAndRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.json")
	_ = os.WriteFile(ok, []byte(`{"self":"s2","default":"s1","shards":{"s1":"cloud.ftw.energy","s2":"s2.cloud.ftw.energy"},"buckets":{"s2":["0-255"]}}`), 0o600)
	d, err := Load(ok)
	if err != nil {
		t.Fatal(err)
	}
	if d.Self() != "s2" || d.Host() != "s2.cloud.ftw.energy" || !d.Ours(homeA) {
		t.Fatalf("%+v", d)
	}
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"self":"s1","default":"s1","shards":{"s1":"cloud.ftw.energy"},"bukets":{}}`), 0o600)
	if _, err := Load(bad); err == nil {
		t.Fatal("a misspelt field was accepted")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
