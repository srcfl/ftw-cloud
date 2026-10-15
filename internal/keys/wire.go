// Package keys is the one part of FTW Cloud that can act on a home. It runs
// as its own process, ftwkeysd, on the same host as ftwcloudd, and answers
// only over a local unix socket.
//
// It holds each agent's X25519 Noise static key, sealed at rest (AWS KMS
// envelope encryption in production, a local file key in development). It
// unseals a key only to open one Noise session with one box, and drops the
// key once the handshake has used it. It keeps the session's transport keys
// and seals and opens each frame of it, so neither an agent's static key nor
// its session keys ever sit in ftwcloudd's memory.
//
// It has no path to a box of its own. It writes and reads Noise messages,
// and ftwcloudd carries them as tun through the box's own uplink, the same
// way it carries a phone's session. The box admits the agent only while its
// signed roster lists the agent's key, and decides what each request may do.
//
// The wire between the two processes is a sequence of frames, each a 4-byte
// big-endian length and one CBOR map: a request {id, op, ...} one way and a
// response {id, err?, ...} the other. Many requests may be in flight on one
// connection.
package keys

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// Operations.
const (
	opNew    = "new"    // make a key pair; answers kid and pub
	opKeep   = "keep"   // the owner approved the agent: keep its key
	opForget = "forget" // delete a key and close its sessions
	opOpen   = "open"   // unseal kid, start a session to rs; answers sess and d (message 1)
	opFinish = "finish" // read message 2 in d
	opSeal   = "seal"   // encrypt frame d of sess; answers d
	opUnseal = "unseal" // decrypt message d of sess; answers d
	opClose  = "close"  // end sess
)

// maxFrame bounds one frame between the processes: one Noise transport
// message around the largest bulk frame, and room for the map around it.
const maxFrame = 64 << 10

type request struct {
	ID   uint64 `cbor:"id"`
	Op   string `cbor:"op"`
	Kid  string `cbor:"kid,omitempty"`
	Sess string `cbor:"sess,omitempty"`
	// RS is the box's Noise static key, for open.
	RS []byte `cbor:"rs,omitempty"`
	D  []byte `cbor:"d,omitempty"`
}

type response struct {
	ID   uint64 `cbor:"id"`
	Err  string `cbor:"err,omitempty"`
	Kid  string `cbor:"kid,omitempty"`
	Pub  []byte `cbor:"pub,omitempty"`
	Sess string `cbor:"sess,omitempty"`
	D    []byte `cbor:"d,omitempty"`
}

// Errors a caller can act on. Each crosses the socket as its text.
var (
	// ErrUnknownKey is a kid the keys part does not hold, or holds only
	// while its approval is pending.
	ErrUnknownKey = errors.New("keys: unknown key")
	// ErrUnknownSession is a session the keys part does not hold: it ended,
	// went idle, or ftwkeysd restarted. Open a new one.
	ErrUnknownSession = errors.New("keys: unknown session")
	// ErrBusy is a keys part at its limit of keys or sessions.
	ErrBusy = errors.New("keys: busy")
	// ErrRefused is a request the keys part will not do as asked.
	ErrRefused = errors.New("keys: refused")
)

var known = []error{ErrUnknownKey, ErrUnknownSession, ErrBusy, ErrRefused}

func errorFrom(s string) error {
	if s == "" {
		return nil
	}
	for _, e := range known {
		if e.Error() == s {
			return e
		}
	}
	return fmt.Errorf("keys: %s", s)
}

// errorText is what crosses the socket for err: one of the known errors, or
// a fixed word. Nothing else, so no detail about a key can leave by way of an
// error message.
func errorText(err error) string {
	for _, e := range known {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "failed"
}

var (
	encMode = mustEnc()
	decMode = mustDec()
)

func mustEnc() cbor.EncMode {
	m, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return m
}

func mustDec() cbor.DecMode {
	m, err := cbor.DecOptions{MaxArrayElements: 16, MaxMapPairs: 16, MaxNestedLevels: 4}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}

func writeFrame(w io.Writer, v any) error {
	body, err := encMode.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > maxFrame {
		return fmt.Errorf("keys: a frame of %d bytes", len(body))
	}
	buf := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(buf, uint32(len(body)))
	copy(buf[4:], body)
	_, err = w.Write(buf)
	return err
}

func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxFrame {
		return fmt.Errorf("keys: a frame of %d bytes", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return decMode.Unmarshal(body, v)
}
