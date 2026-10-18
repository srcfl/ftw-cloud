package store

import (
	"bytes"
	"testing"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

func TestAgentInviteIsNotAPhoneCodeAndSurvivesLostHandshake(t *testing.T) {
	hash := bytes.Repeat([]byte{0x73}, 32)
	r := tunRoster(1, true)
	r.Pending = []cloudwire.Pending{{Kind: protocol.RoleAgent, Hash: hash, TTLS: 7200}}
	s, box, _ := tunHome(t, r)
	box.Put(cloudwire.MsgLive, []byte("private reading"), 2, true)
	if _, err := s.For(Principal{Kind: Device, Home: "h1", DeviceKey: newKey, Pair: hash}); err == nil {
		t.Fatal("agent hint paired a phone")
	}
	if _, err := s.For(Principal{Kind: Agent, Home: "h1", DeviceKey: newKey}); err == nil {
		t.Fatal("hint admitted ordinary agent")
	}
	for range 2 {
		h, err := s.For(Principal{Kind: AgentInvite, Home: "h1", DeviceKey: newKey, Invite: hash})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, session, err := h.Open()
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Envelopes) != 0 || h.MayRead(cloudwire.MsgHB) {
			t.Fatal("unapproved key read home's copy")
		}
		session.Close() // A lost handshake must not spend the invitation.
	}
	h, _ := s.For(Principal{Kind: AgentInvite, Home: "h1", DeviceKey: newKey, Invite: hash})
	_, session, err := h.Open()
	if err != nil {
		t.Fatal(err)
	}
	r.RosterSeq = 2
	r.Pending = nil
	box.SetRoster(r)
	select {
	case <-session.Done():
	default:
		t.Fatal("cancelled invitation left bootstrap session open")
	}
	if _, err := s.For(Principal{Kind: AgentInvite, Home: "h1", DeviceKey: newKey, Invite: hash}); err == nil {
		t.Fatal("cancelled hint remained")
	}
}
