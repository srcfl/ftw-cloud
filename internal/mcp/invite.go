package mcp

import (
	"context"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// ClaimInvite runs one short bootstrap session. It never puts a pending key
// in the warm MCP pool and never grants a token; OAuth waits for the roster.
func (p *Pool) ClaimInvite(ctx context.Context, m oauth.InviteClaim) error {
	if p.draining.Load() {
		return errRestarting
	}
	c := &agentConn{p: p, home: m.Home, agent: cloudwire.DeviceID(m.Key), ready: make(chan struct{}), done: make(chan struct{}), turn: make(chan struct{}, 1),
		waiting: map[uint32]chan appwire.Envelope{}, byCmd: map[string]chan appwire.Envelope{}, helloReady: make(chan struct{}), used: p.now()}
	defer c.close(nil)
	sub := oauth.Subject{Home: m.Home, Agent: c.agent, Kid: m.Kid, Key: m.Key}
	if err := c.openFor(ctx, sub, &m); err != nil {
		return err
	}
	select {
	case <-c.helloReady:
		c.mu.Lock()
		err := c.helloErr
		c.mu.Unlock()
		return err
	case <-c.done:
		return errEnded
	case <-ctx.Done():
		return errTimeout
	}
}
