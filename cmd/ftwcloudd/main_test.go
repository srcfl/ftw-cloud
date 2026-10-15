package main

import (
	"testing"
	"time"
)

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
