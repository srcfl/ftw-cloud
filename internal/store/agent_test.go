package store

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

var agentKey = bytes.Repeat([]byte{7}, 32)

// rosterWithAgent lists the owner, the viewer and one agent row that ends
// at end, with empty copy scopes, as the contract has it.
func rosterWithAgent(seq uint64, end time.Time) *cloudwire.Roster {
	r := roster(seq, protocol.ScopeLiveRead)
	r.Devices = append(r.Devices, cloudwire.Device{ID: cloudwire.DeviceID(agentKey), Key: agentKey, Role: protocol.RoleAgent,
		Scopes: []string{}, Epoch: 1, Tun: true,
		Agent: &cloudwire.Agent{Scopes: []string{protocol.ScopeLiveRead}, ExpiresAtMs: end.UnixMilli()}})
	return r
}

// An agent row is admitted only as an agent: never as a phone, which keeps
// it off /v1/app and /v1/app/once, and never by a token. A phone's row is
// never an agent. And the store stops admitting an agent at its end, by its
// own clock, without waiting for a roster.
func TestAgentRowsOnlyAsAgentsAndOnlyUntilTheirEnd(t *testing.T) {
	s, box, c := filled(t)
	end := c.t.Add(time.Hour)
	box.SetRoster(rosterWithAgent(2, end))

	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: agentKey}); !errors.Is(err, ErrDenied) {
		t.Fatalf("an agent row as a phone: %v", err)
	}
	if _, err := s.For(Principal{Kind: Token, Home: "h1", DeviceID: cloudwire.DeviceID(agentKey), Epoch: 1}); !errors.Is(err, ErrDenied) {
		t.Fatalf("an agent row by a token: %v", err)
	}
	if _, err := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: ownerKey}); !errors.Is(err, ErrDenied) {
		t.Fatalf("a phone as an agent: %v", err)
	}
	h, err := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: agentKey})
	if err != nil {
		t.Fatal(err)
	}
	snap, sess, err := h.Open()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Envelopes) != 0 {
		t.Fatal("an agent got readings from the copy")
	}
	// The copy's readings do not reach it either.
	_ = box.Put(cloudwire.MsgLive, []byte("live-2"), 8, true)
	select {
	case <-sess.C():
		t.Fatal("an agent session received a reading")
	default:
	}

	c.t = end
	if _, err := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: agentKey}); !errors.Is(err, ErrDenied) {
		t.Fatalf("an agent at its end: %v", err)
	}
	if _, _, err := h.Open(); !errors.Is(err, ErrDenied) {
		t.Fatalf("a session opened at the agent's end: %v", err)
	}
}

// A roster that drops the agent ends its session.
func TestARosterWithoutTheAgentEndsItsSession(t *testing.T) {
	s, box, c := filled(t)
	box.SetRoster(rosterWithAgent(2, c.t.Add(time.Hour)))
	h, _ := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: agentKey})
	_, sess, err := h.Open()
	if err != nil {
		t.Fatal(err)
	}
	box.SetRoster(roster(3, protocol.ScopeLiveRead))
	select {
	case <-sess.Done():
	default:
		t.Fatal("the agent's session outlived its row")
	}
}
