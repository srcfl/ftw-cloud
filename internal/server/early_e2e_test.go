package server

import (
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

	mu      sync.Mutex
	flights map[string]*flight
	order   []string
}

type flight struct {
	up      *net.UDPConn
	packets [][]byte
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
		_, _ = f.up.Write(pkt)
	}
}

// first is the first flight of the n-th client.
func (r *flightRecorder) first(n int) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.flights[r.order[n]].packets)
}

// A phone's second connection carries its Noise message 1, and the box
// session's message 1 inside it, in early data: one round trip sooner. A
// network that replays that flight later, from another address, changes
// nothing: the door holds the copy back, the box hears no handshake and no
// watch, and the phone's live session is not replaced.
func TestAReplayedEarlyFlightChangesNothing(t *testing.T) {
	s := newStack(t)
	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	rec := newFlightRecorder(t, s.quic())
	cache := tls.NewLRUClientSessionCache(4)
	dial := func(cache tls.ClientSessionCache) *quicdoor.Conn {
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
	now := cloudwire.Now{Hz: cloudwire.HzLooking}

	// The first connection holds no ticket; it leaves with one.
	first := newTunPhone(t, key)
	first.session(dial(cache), s.noise.Public(), box.home, now)
	if first.tr == nil {
		t.Fatalf("the first session did not open: %d", first.code)
	}
	first.open(box.static.Public(), 21, nil)
	time.Sleep(100 * time.Millisecond)
	_ = first.conn.Close()

	// The second resumes and sends message 1 in early data.
	second := newTunPhone(t, key)
	conn := dial(cache)
	second.session(conn, s.noise.Public(), box.home, cloudwire.Now{Hz: cloudwire.HzLooking,
		Tun: &cloudwire.AppTun{Sid: 22, D: second.boxMessage1(box.static.Public(), nil)}})
	if second.tr == nil {
		t.Fatalf("the early session did not open: %d", second.code)
	}
	if !conn.UsedEarlyData() {
		t.Fatal("the second connection did not use early data")
	}
	second.boxMessage2(second.next().D)
	if ack, _ := second.cmd(22, "early"); ack != protocol.MsgCmdAck {
		t.Fatal("no ack on the early session")
	}
	flightOfSecond := rec.first(1)
	_ = conn.Close()

	// The phone's live session now, over the WebSocket, which the replay
	// must not replace.
	live := s.dialPhone(box.home, key, cloudwire.Now{}, "")
	if live.tr == nil {
		t.Fatal("the live session did not open")
	}
	live.open(box.static.Public(), 23, nil)
	// Wait out quic-go's memory of the closed connection, so the replay
	// reaches the door as a connection of its own.
	time.Sleep(1500 * time.Millisecond)

	handshakes := box.handshakes()
	box.mu.Lock()
	heard := len(box.heard)
	box.mu.Unlock()
	repeats := s.door.EarlyRepeats.Load()

	replay, err := net.DialUDP("udp", nil, mustUDP(t, s.quic()))
	if err != nil {
		t.Fatal(err)
	}
	defer replay.Close()
	for _, p := range flightOfSecond {
		if _, err := replay.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	// The replayer cannot finish the handshake; give the door every chance
	// to act on what it got.
	time.Sleep(1500 * time.Millisecond)

	if got := s.door.EarlyRepeats.Load(); got != repeats+1 {
		t.Fatalf("the door held back %d copies of message 1, want 1: the replay never reached it", got-repeats)
	}
	if got := box.handshakes(); got != handshakes {
		t.Fatalf("the replay reached the box: %d handshakes", got-handshakes)
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
}

func mustUDP(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
