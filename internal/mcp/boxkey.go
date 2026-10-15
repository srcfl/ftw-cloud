package mcp

import (
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Rosters gives a home's newest signed roster: package registry.
type Rosters interface {
	Get(home string) (registry.Home, bool, error)
}

// RosterBoxKey reads a home's box Noise static key from the roster its box
// signed (Roster.Noise, srcfl/ftw docs/agents.md): the newest one the registry
// holds, checked again with the home's key, so the service opens an agent's
// session only to a key the box itself named. A roster without one is a box
// that takes no agents yet.
func RosterBoxKey(r Rosters) BoxKey {
	return func(home string) ([]byte, bool) {
		h, ok, err := r.Get(home)
		if err != nil || !ok || len(h.Roster) == 0 {
			return nil, false
		}
		pub, err := cloudwire.ParsePublicKey(h.PK)
		if err != nil || cloudwire.HomeID(h.PK) != home {
			return nil, false
		}
		env, err := cloudwire.DecodeEnvelope(h.Roster)
		if err != nil || env.T != cloudwire.MsgRoster || cloudwire.Verify(pub, home, env) != nil {
			return nil, false
		}
		var r cloudwire.Roster
		if cloudwire.Unmarshal(env.B, &r) != nil || len(r.Noise) != appwire.DHBytes {
			return nil, false
		}
		return r.Noise, true
	}
}
