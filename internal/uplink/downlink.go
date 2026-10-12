package uplink

import (
	"fmt"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// down is a message the service may send a box. The method is unexported, so
// only the five types below implement it and a sixth cannot be sent by
// accident. TestDownlinkIsTheProtocolsClosedSet holds the list to
// cloudwire.Downlink, and the box closes the uplink on anything else.
//
// None of the five asks the box to act. watch asks it to send sooner, resync
// to send again, and purged confirms a deletion the box asked for.
type down interface {
	down() (t string, body any, signed bool)
}

type (
	challenge cloudwire.Challenge
	helloOK   cloudwire.HelloOK
	watch     cloudwire.Watch
	resync    cloudwire.Resync
	purged    cloudwire.Purged
)

func (m challenge) down() (string, any, bool) {
	return cloudwire.MsgChallenge, cloudwire.Challenge(m), false
}
func (m helloOK) down() (string, any, bool) { return cloudwire.MsgHelloOK, cloudwire.HelloOK(m), true }
func (m watch) down() (string, any, bool)   { return cloudwire.MsgWatch, cloudwire.Watch(m), false }
func (m resync) down() (string, any, bool)  { return cloudwire.MsgResync, cloudwire.Resync(m), false }
func (m purged) down() (string, any, bool)  { return cloudwire.MsgPurged, cloudwire.Purged(m), true }

// encodeDown frames one downlink message. hello_ok and purged are signed with
// the service key over the box's home id; the rest are not.
func (u *Uplink) encodeDown(home string, m down) ([]byte, error) {
	t, body, signed := m.down()
	key := u.key
	if !signed {
		key = nil
	}
	env, err := cloudwire.Seal(key, home, t, body)
	if err != nil {
		return nil, err
	}
	raw, err := env.Encode()
	if err != nil {
		return nil, err
	}
	frame, err := cloudwire.EncodeFrame(raw)
	if err != nil {
		return nil, err
	}
	if len(frame) > cloudwire.MaxServiceFrame {
		return nil, fmt.Errorf("uplink: %s is %d bytes, over the box's limit", t, len(frame))
	}
	return frame, nil
}

func (c *boxConn) send(m down) error {
	frame, err := c.u.encodeDown(c.home, m)
	if err != nil {
		return err
	}
	return c.write(frame)
}
