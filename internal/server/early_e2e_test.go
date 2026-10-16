package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/quicdoor"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// flightRecorder is a UDP proxy in front of the door that keeps, for each
// client, its first flight as a network could: every Initial and 0-RTT
// packet it sent, the ClientHello and the early data. It holds the door's
// answers back 30 ms, as a real path does, so a client writes its first
// messages before the handshake can finish.
type flightRecorder struct {
	t    *testing.T
	pc   net.PacketConn
	door *net.UDPAddr
	// dropNext makes the next new client's packets go nowhere, as a
	// network that records a flight and drops it.
	dropNext bool

	mu      sync.Mutex
	flights map[string]*flight
	order   []string
}

type flight struct {
	up      *net.UDPConn
	packets [][]byte
	dropped bool
}

func newFlightRecorder(t *testing.T, door string) *flightRecorder {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addr, _ := net.ResolveUDPAddr("udp", door)
	r := &flightRecorder{t: t, pc: pc, door: addr, flights: map[string]*flight{}}
	go r.run()
	return r
}

func (r *flightRecorder) addr() string { return r.pc.LocalAddr().String() }

func (r *flightRecorder) run() {
	buf := make([]byte, 2048)
	for {
		n, from, err := r.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		r.mu.Lock()
		f := r.flights[from.String()]
		if f == nil && r.dropNext {
			r.dropNext = false
			f = &flight{dropped: true}
			r.flights[from.String()] = f
			r.order = append(r.order, from.String())
		}
		if f == nil {
			up, err := net.DialUDP("udp", nil, r.door)
			if err != nil {
				r.mu.Unlock()
				continue
			}
			f = &flight{up: up}
			r.flights[from.String()] = f
			r.order = append(r.order, from.String())
			go func(client net.Addr) {
				b := make([]byte, 2048)
				for {
					n, err := up.Read(b)
					if err != nil {
						return
					}
					pkt := append([]byte(nil), b[:n]...)
					time.AfterFunc(30*time.Millisecond, func() { _, _ = r.pc.WriteTo(pkt, client) })
				}
			}(from)
		}
		// A long header of type Initial (0) or 0-RTT (1).
		if pkt[0]&0x80 != 0 && (pkt[0]>>4)&3 <= 1 {
			f.packets = append(f.packets, pkt)
		}
		r.mu.Unlock()
		if !f.dropped {
			_, _ = f.up.Write(pkt)
		}
	}
}

// drop makes the next new client's flight go nowhere.
func (r *flightRecorder) drop() {
	r.mu.Lock()
	r.dropNext = true
	r.mu.Unlock()
}

// first is the first flight of the n-th client.
func (r *flightRecorder) first(n int) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.flights[r.order[n]].packets)
}

// A network records a phone's early flight and drops it. The phone dials
// again, over the WebSocket, and only then does the network replay the
// flight. That changes nothing: the door holds the copy for a handshake its
// sender cannot finish, so the live session is not replaced, the box hears
// no handshake and no watch, and a pairing code in a flight stays unspent.
func TestADroppedEarlyFlightReplayedLaterChangesNothing(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	known, _ := appwire.GenerateKeyPair()
	code := bytes.Repeat([]byte{0x42}, 16)
	box.roster(2, grantOff, code, known.Public())
	waitRoster(t, s, box.home, known)
	rec := newFlightRecorder(t, s.quic())
	cache := tls.NewLRUClientSessionCache(4)
	dial := func() *quicdoor.Conn {
		t.Helper()
		tc := s.clientTLS()
		tc.ClientSessionCache = cache
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, err := quicdoor.Dial(ctx, rec.addr(), tc, cloudwire.ALPNApp, cloudwire.AppTarget(box.home), nil)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// ticket makes one connection that completes its handshake and keeps
	// the ticket it leaves with.
	ticket := func() {
		t.Helper()
		c := dial()
		select {
		case <-c.QUIC().HandshakeComplete():
		case <-time.After(3 * time.Second):
			t.Fatal("no handshake")
		}
		time.Sleep(100 * time.Millisecond)
		_ = c.Close()
	}
	// early dials with the ticket and sends message 1 in early data into a
	// network that drops it.
	early := func(key appwire.KeyPair, now cloudwire.Now) {
		t.Helper()
		rec.drop()
		p := newTunPhone(t, key)
		c := dial()
		p.session(c, s.noise.Public(), box.home, now)
		if p.tr != nil {
			t.Fatal("a dropped flight opened a session")
		}
	}
	// carriesEarlyData reports whether a flight holds a 0-RTT packet: a long
	// header of type 1.
	carriesEarlyData := func(flight [][]byte) bool {
		return slices.ContainsFunc(flight, func(p []byte) bool { return p[0]&0x80 != 0 && (p[0]>>4)&3 == 1 })
	}

	ticket()
	pairing, _ := appwire.GenerateKeyPair()
	early(pairing, cloudwire.Now{Hz: cloudwire.HzLooking, Pair: cloudwire.PairingHash(box.home, code)})
	flightOfPairing := rec.first(1)
	ticket()
	early(known, cloudwire.Now{Hz: cloudwire.HzLooking,
		Tun: &cloudwire.AppTun{Sid: 31, D: newTunPhone(t, known).boxMessage1(box.static.Public(), nil)}})
	flightOfKnown := rec.first(3)
	if !carriesEarlyData(flightOfPairing) || !carriesEarlyData(flightOfKnown) {
		t.Fatal("a recorded flight carried no early data")
	}

	// The known phone dials again, over the WebSocket: its live session.
	live := s.dialPhone(box.home, known, cloudwire.Now{}, "")
	if live.tr == nil {
		t.Fatal("the live session did not open")
	}
	live.open(box.static.Public(), 23, nil)

	handshakes := box.handshakes()
	box.mu.Lock()
	heard := len(box.heard)
	box.mu.Unlock()
	held := s.door.EarlyHeld.Load()
	for _, flight := range [][][]byte{flightOfKnown, flightOfPairing} {
		replay, err := net.DialUDP("udp", nil, mustUDP(t, s.quic()))
		if err != nil {
			t.Fatal(err)
		}
		defer replay.Close()
		for _, p := range flight {
			if _, err := replay.Write(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The replayer cannot finish the handshake; give the door every chance
	// to act on what it got.
	time.Sleep(1500 * time.Millisecond)

	if got := s.door.EarlyHeld.Load() - held; got != 2 {
		t.Fatalf("the door held %d replayed sessions for the handshake, want 2: a replay never reached it", got)
	}
	if got := box.handshakes(); got != handshakes {
		t.Fatalf("a replay reached the box: %d handshakes", got-handshakes)
	}
	box.mu.Lock()
	since := slices.Clone(box.heard[heard:])
	box.mu.Unlock()
	for _, typ := range since {
		if typ == cloudwire.MsgWatch || typ == cloudwire.MsgTun {
			t.Fatalf("the box heard %q after the replay", typ)
		}
	}
	if ack, res := live.cmd(23, "after the replay"); ack != protocol.MsgCmdAck || res != protocol.CmdApplied {
		t.Fatalf("the live session after the replay: %q %q", ack, res)
	}
	if live.ended != nil {
		t.Fatalf("the live session ended: %v", live.ended)
	}
	// The pairing code is still there for the phone that holds it.
	if p := s.dialPhone(box.home, pairing, cloudwire.Now{Hz: 1, Pair: cloudwire.PairingHash(box.home, code)}, ""); p.tr == nil {
		t.Fatalf("the replay spent the pairing code: refused with %d", p.code)
	}
}

func mustUDP(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
