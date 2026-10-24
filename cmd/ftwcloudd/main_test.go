package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/metrics"
)

// Every series the service keeps, which /v1/ops keeps for 90 days, carries
// only labels from this list, each a word fixed in the code. A label that
// could hold a home, a device or an address is a change to argue for here.
func TestCountsNameNobody(t *testing.T) {
	var b strings.Builder
	if _, err := metrics.Default.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	pair := regexp.MustCompile(`([a-z_]+)="([^"]*)"`)
	word := regexp.MustCompile(`^[a-z0-9_]{1,40}$|^[0-9.e+-]+$|^\+Inf$`)
	allowed := []string{"kind", "reason", "path", "dir", "result", "transport", "outcome", "le"}
	n := 0
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		n++
		for _, m := range pair.FindAllStringSubmatch(line, -1) {
			if !slices.Contains(allowed, m[1]) || !word.MatchString(m[2]) {
				t.Fatalf("label %s=%q in %s", m[1], m[2], line)
			}
		}
	}
	if n < 50 {
		t.Fatalf("only %d series: is every package's set registered?", n)
	}
}

func TestTheRestartSpreadFollowsTheSockets(t *testing.T) {
	for _, c := range []struct {
		sockets, rate int
		want          time.Duration
	}{
		{0, 500, 15 * time.Second},
		{4000, 500, 15 * time.Second},
		{12000, 500, 24 * time.Second},
		{1_000_000, 500, 60 * time.Second},
		{12000, 0, 24 * time.Second},
	} {
		if got := restartSpread(c.sockets, c.rate, 15*time.Second); got != c.want {
			t.Errorf("restartSpread(%d, %d) = %s, want %s", c.sockets, c.rate, got, c.want)
		}
	}
}
