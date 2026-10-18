package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
)

func poolTestConn(p *Pool, name string, used time.Time) *agentConn {
	c := &agentConn{p: p, home: name, agent: "agent", used: used,
		ready: make(chan struct{}), done: make(chan struct{}), turn: make(chan struct{}, 1)}
	close(c.ready)
	p.conns[connKey{c.home, c.agent}] = c
	return c
}

func TestCapacityEvictionKeepsActiveQueuedAndOpeningSessions(t *testing.T) {
	p := &Pool{conns: map[connKey]*agentConn{}}
	now := time.Now()
	active := poolTestConn(p, "active", now.Add(-4*time.Minute))
	active.turn <- struct{}{}
	queued := poolTestConn(p, "queued", now.Add(-3*time.Minute))
	queued.queued = 1
	opening := poolTestConn(p, "opening", now.Add(-2*time.Minute))
	opening.ready = make(chan struct{})
	idle := poolTestConn(p, "idle", now.Add(-time.Minute))
	p.mu.Lock()
	if !p.evictLocked() {
		t.Fatal("idle session was not evicted")
	}
	if p.evictLocked() {
		t.Fatal("busy or opening session was evicted")
	}
	p.mu.Unlock()
	select {
	case <-idle.done:
	case <-time.After(time.Second):
		t.Fatal("evicted session did not close")
	}
	for _, c := range []*agentConn{active, queued, opening} {
		if c.ended() || c.evicting {
			t.Fatal("busy or opening session was marked for eviction")
		}
	}
	if _, err := idle.take(context.Background()); !errors.Is(err, errIdle) {
		t.Fatalf("borrowed session could start after eviction: %v", err)
	}
}

func TestFullPoolOfActiveSessionsRefusesNewWorkWithoutExceedingItsBound(t *testing.T) {
	p := &Pool{conns: map[connKey]*agentConn{}, now: time.Now}
	for i := range maxConns {
		c := poolTestConn(p, fmt.Sprint(i), time.Now())
		c.turn <- struct{}{}
	}
	if _, err := p.get(context.Background(), oauth.Subject{Home: "another", Agent: "agent"}); !errors.Is(err, errBusy) {
		t.Fatalf("full busy pool: %v", err)
	}
	if got := p.Warm(); got != maxConns {
		t.Fatalf("pool has %d connections, want %d", got, maxConns)
	}
}
