package uplink

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// xConnect connects a box that lists x in hello.caps, or none when caps is
// empty, and waits until its connection is the home's.
func xConnect(t *testing.T, s *service, caps ...string) *box {
	t.Helper()
	b := newBox(t)
	b.caps = caps
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	wait(t, "the box is the home's", func() bool {
		s.up.mu.Lock()
		defer s.up.mu.Unlock()
		return s.up.conns[b.home] != nil
	})
	return b
}

// ask runs one exchange in the background; its answer comes on the channel.
func ask(s *service, home, dev string, d []byte) <-chan []byte {
	out := make(chan []byte, 1)
	go func() { out <- s.up.Exchange(context.Background(), home, dev, d) }()
	return out
}

// answered waits for an exchange's answer and how long it took from start.
func answered(t *testing.T, got <-chan []byte, start time.Time) ([]byte, time.Duration) {
	t.Helper()
	select {
	case a := <-got:
		return a, time.Since(start)
	case <-time.After(10 * time.Second):
		t.Fatal("the exchange never ended")
		return nil, 0
	}
}

// readX reads the next x the service sent the box.
func (b *box) readX() cloudwire.X {
	b.t.Helper()
	env := b.read()
	var x cloudwire.X
	if env.T != cloudwire.MsgX || len(env.Sig) != 0 || cloudwire.Unmarshal(env.B, &x) != nil {
		b.t.Fatalf("the box got %q", env.T)
	}
	return x
}

// sendX sends the box's x, unsigned, as the box does.
func (b *box) sendX(x any) {
	body, _ := cloudwire.Marshal(x)
	raw, _ := cloudwire.Envelope{T: cloudwire.MsgX, B: body}.Encode()
	frame, _ := cloudwire.EncodeFrame(raw)
	_ = b.conn.WriteMessage(websocket.BinaryMessage, frame)
}

// An exchange goes down under the device the service names and the service's
// own number, and the box's answer under the same comes back unchanged.
func TestAnExchangeReachesItsBoxAndComesBack(t *testing.T) {
	s := newService(t)
	b := xConnect(t, s, cloudwire.CapX)
	start := time.Now()
	got := ask(s, b.home, "watch", []byte("message 1"))
	x := b.readX()
	if x.Dev != "watch" || x.ID == 0 || string(x.D) != "message 1" {
		t.Fatalf("the box got %+v", x)
	}
	b.sendX(cloudwire.X{Dev: x.Dev, ID: x.ID, D: []byte("message 2")})
	if a, _ := answered(t, got, start); string(a) != "message 2" {
		t.Fatalf("the watch got %q", a)
	}
	// An empty answer is the box's silence, and goes back empty.
	got = ask(s, b.home, "watch", []byte("spent"))
	x = b.readX()
	b.sendX(cloudwire.X{Dev: x.Dev, ID: x.ID})
	if a, _ := answered(t, got, start); len(a) != 0 {
		t.Fatalf("the watch got %q", a)
	}
}

// Two watches of one home with exchanges open each get their own answer,
// whatever order the box answers in, and an answer under another device is
// nobody's.
func TestEachWatchGetsItsOwnAnswer(t *testing.T) {
	s := newService(t)
	b := xConnect(t, s, cloudwire.CapX)
	start := time.Now()
	one := ask(s, b.home, "one", []byte("from one"))
	x1 := b.readX()
	two := ask(s, b.home, "two", []byte("from two"))
	x2 := b.readX()
	if x1.ID == x2.ID {
		t.Fatalf("two exchanges under one number %d", x1.ID)
	}
	before := dropXUnknown.Load()
	b.sendX(cloudwire.X{Dev: "two", ID: x1.ID, D: []byte("stolen")})
	b.sendX(cloudwire.X{Dev: "two", ID: x2.ID, D: []byte("for two")})
	b.sendX(cloudwire.X{Dev: "one", ID: x1.ID, D: []byte("for one")})
	if a, _ := answered(t, two, start); string(a) != "for two" {
		t.Fatalf("two got %q", a)
	}
	if a, _ := answered(t, one, start); string(a) != "for one" {
		t.Fatalf("one got %q", a)
	}
	if n := dropXUnknown.Load() - before; n != 1 {
		t.Fatalf("dropped %d", n)
	}
}

// An answer nobody waits for is dropped and counted, and the box stays.
func TestAnAnswerNobodyWaitsForIsDropped(t *testing.T) {
	s := newService(t)
	b := xConnect(t, s, cloudwire.CapX)
	before := dropXUnknown.Load()
	b.sendX(cloudwire.X{Dev: "watch", ID: 99, D: []byte{1}})
	wait(t, "the drop", func() bool { return dropXUnknown.Load() == before+1 })
	start := time.Now()
	got := ask(s, b.home, "watch", []byte{2})
	x := b.readX()
	b.sendX(cloudwire.X{Dev: x.Dev, ID: x.ID, D: []byte{3}})
	if a, _ := answered(t, got, start); !bytes.Equal(a, []byte{3}) {
		t.Fatalf("after the drop the watch got %v", a)
	}
}

// No answer is an empty one: at once with no box, a box that does not take
// x or XInFlight open, and after the wait for a box that keeps silent.
func TestNoAnswerIsEmpty(t *testing.T) {
	t.Run("no box", func(t *testing.T) {
		s := newService(t)
		start := time.Now()
		a, took := answered(t, ask(s, newBox(t).home, "watch", []byte{1}), start)
		if a != nil || took > 500*time.Millisecond {
			t.Fatalf("%v after %v", a, took)
		}
	})
	t.Run("a box without x", func(t *testing.T) {
		s := newService(t)
		b := xConnect(t, s, cloudwire.CapTun)
		start := time.Now()
		a, took := answered(t, ask(s, b.home, "watch", []byte{1}), start)
		if a != nil || took > 500*time.Millisecond {
			t.Fatalf("%v after %v", a, took)
		}
		_ = b.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := b.conn.ReadMessage(); err == nil || !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("a box without x heard something: %v", err)
		}
	})
	t.Run("a silent box", func(t *testing.T) {
		s := newService(t)
		s.up.xWithin = 300 * time.Millisecond
		b := xConnect(t, s, cloudwire.CapX)
		start := time.Now()
		got := ask(s, b.home, "watch", []byte{1})
		b.readX()
		a, took := answered(t, got, start)
		if a != nil || took < 300*time.Millisecond || took > 2*time.Second {
			t.Fatalf("%v after %v", a, took)
		}
	})
	t.Run("past XInFlight", func(t *testing.T) {
		s := newService(t)
		b := xConnect(t, s, cloudwire.CapX)
		var open []<-chan []byte
		for range cloudwire.XInFlight {
			open = append(open, ask(s, b.home, "watch", []byte{1}))
			b.readX()
		}
		before := dropXBusy.Load()
		start := time.Now()
		a, took := answered(t, ask(s, b.home, "watch", []byte{1}), start)
		if a != nil || took > 500*time.Millisecond || dropXBusy.Load() != before+1 {
			t.Fatalf("%v after %v", a, took)
		}
		_ = b.conn.Close()
		for _, got := range open {
			answered(t, got, start)
		}
	})
}

// When the box's connection ends, every exchange waiting on it is answered,
// empty, at once rather than after the wait.
func TestTheEndOfAnUplinkAnswersEveryExchange(t *testing.T) {
	s := newService(t)
	b := xConnect(t, s, cloudwire.CapX)
	one, two := ask(s, b.home, "one", []byte{1}), ask(s, b.home, "two", []byte{2})
	b.readX()
	b.readX()
	start := time.Now()
	_ = b.conn.Close()
	for _, got := range []<-chan []byte{one, two} {
		if a, took := answered(t, got, start); a != nil || took > time.Second {
			t.Fatalf("%v after %v", a, took)
		}
	}
}

// An x the service cannot route closes the uplink, as a tun does.
func TestAMalformedXCloses(t *testing.T) {
	for name, send := range map[string]func(b *box){
		"signed":     func(b *box) { b.send(cloudwire.MsgX, cloudwire.X{Dev: "watch", ID: 1, D: []byte{1}}) },
		"no device":  func(b *box) { b.sendX(cloudwire.X{ID: 1, D: []byte{1}}) },
		"d too long": func(b *box) { b.sendX(cloudwire.X{Dev: "watch", ID: 1, D: make([]byte, cloudwire.XDataMax+1)}) },
		"not an x":   func(b *box) { b.sendX(map[string]any{"dev": 7, "id": "one"}) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newService(t)
			b := xConnect(t, s, cloudwire.CapX)
			send(b)
			if !b.closed() {
				t.Fatal("the box stayed")
			}
		})
	}
}
