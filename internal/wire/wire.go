// Package wire is what the uplink and the app session need of a connection,
// so that the same handlers serve a box or a phone over a WebSocket and over
// QUIC (package quicdoor). A *websocket.Conn is a Conn as it is.
//
// QUIC adds two ways for a message to travel beside the control stream, each
// a message type of its own. A handler asks for one with Kind, which falls
// back to a binary message on a connection that lacks it, so it never has to
// know which transport it serves.
package wire

import (
	"time"

	"github.com/gorilla/websocket"
)

// Conn is a message connection: gorilla/websocket's method set.
type Conn interface {
	ReadMessage() (messageType int, p []byte, err error)
	WriteMessage(messageType int, data []byte) error
	WriteControl(messageType int, data []byte, deadline time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetReadLimit(limit int64)
	SetPongHandler(h func(appData string) error)
	Close() error
}

// Message types beyond the WebSocket's. A Conn that reads one says how the
// message came; one that is asked to write one sends it that way.
const (
	// Bulk is a message on the bulk stream: a tun carrying a lane 1 frame of
	// the phone's session, which must not hold up lane 0.
	Bulk = 0x100
	// Datagram is a QUIC DATAGRAM: never sent again, the newest wins.
	Datagram = 0x101
)

// Carrier is what a Conn that offers more than binary messages reports.
type Carrier interface {
	// Carries reports whether the connection can send messages of this
	// type now. A datagram needs the peer to have offered datagrams.
	Carries(messageType int) bool
	// Transport is the registry's name for it: quic or websocket.
	Transport() string
}

// Kind is the message type to write a message of the wanted type with on
// conn: the wanted one where the connection carries it, a binary message
// anywhere else.
func Kind(conn Conn, want int) int {
	if want == websocket.BinaryMessage {
		return want
	}
	if c, ok := conn.(Carrier); ok && c.Carries(want) {
		return want
	}
	return websocket.BinaryMessage
}

// Data reports whether a message type read from a Conn carries the
// protocol: a binary message, or one of QUIC's.
func Data(messageType int) bool {
	return messageType == websocket.BinaryMessage || messageType == Bulk || messageType == Datagram
}
