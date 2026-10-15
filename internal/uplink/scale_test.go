package uplink

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

func closeCode(err error) (int, string) {
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		return ce.Code, ce.Text
	}
	return 0, ""
}

// twoShards puts home on s2 and makes this instance s1.
func twoShards(t *testing.T, home string) *shard.Directory {
	t.Helper()
	d, err := shard.File{Self: "s1", Default: "s1",
		Shards: map[string]string{"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
		Homes:  map[string]string{home: "s2"}}.Directory()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A box whose home another shard holds hears that shard's host after
// hello, and leaves nothing in this instance's registry.
func TestABoxOfAnotherShardIsSentThere(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	s.up.Shards = twoShards(t, b.home)
	before := wrongShard.Load()
	_, err := b.connect(s, nil)
	if code, host := closeCode(err); code != cloudwire.CloseWrongShard || host != "s2.cloud.ftw.energy" {
		t.Fatalf("close %d %q (%v)", code, host, err)
	}
	if _, ok, _ := s.reg.Get(b.home); ok {
		t.Fatal("a home of another shard was claimed here")
	}
	if wrongShard.Load() != before+1 {
		t.Fatal("not counted")
	}
	// A home of this shard connects as before.
	other := newBox(t)
	if _, err := other.connect(s, nil); err != nil {
		t.Fatal(err)
	}
}

// A box that redials faster than its home's connect limit is turned away
// before it touches the registry; its tunnel limits carry over to the next
// connection.
func TestABoxThatRedialsFastIsTurnedAway(t *testing.T) {
	s := newService(t)
	b := newBox(t)
	for range connectBurst {
		if _, err := b.connect(s, nil); err != nil {
			t.Fatal(err)
		}
		_ = b.conn.Close()
	}
	before := dropConnect.Load()
	_, err := b.connect(s, nil)
	if code, _ := closeCode(err); code != cloudwire.CloseBusy {
		t.Fatalf("close %d (%v)", code, err)
	}
	if dropConnect.Load() != before+1 {
		t.Fatal("not counted")
	}
}

func TestTunLimitsOutliveTheConnection(t *testing.T) {
	s := newService(t)
	b := tunConnect(t, s)
	wait(t, "the box is the home's", func() bool { return s.up.Tun(b.home, cloudwire.Tun{Dev: "owner", Sid: 1}) })
	lim := s.up.limitsFor(b.home)
	s.up.release(lim)
	lim.take(func() bool {
		lim.downMsgs.tokens = -1e6 // empty for longer than the test runs
		return true
	})
	_ = b.conn.Close()
	wait(t, "the box is gone", func() bool { return s.up.Boxes() == 0 })
	tunConnectAs(t, s, b)
	before := dropTunDown.Load()
	wait(t, "the box is back", func() bool { return s.up.Boxes() == 1 })
	s.up.Tun(b.home, cloudwire.Tun{Dev: "owner", Sid: 1, D: []byte{1}})
	if dropTunDown.Load() != before+1 {
		t.Fatal("a reconnect refilled the home's tunnel")
	}
}

// Drain closes every box with CloseRestart and the spread, and their
// absence starts no box.unreachable.
func TestDrainSendsEveryBoxToComeBack(t *testing.T) {
	s := newService(t)
	gone := 0
	s.up.OnGone = func(string, string, uint64) { gone++ }
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	wait(t, "the box is the home's", func() bool { return s.up.Boxes() == 1 })
	if n := s.up.Drain("3000"); n != 1 {
		t.Fatalf("drained %d", n)
	}
	_, _, err := b.conn.ReadMessage()
	if code, reason := closeCode(err); code != cloudwire.CloseRestart || reason != "3000" {
		t.Fatalf("close %d %q (%v)", code, reason, err)
	}
	wait(t, "the box is gone", func() bool { return s.up.Boxes() == 0 })
	if gone != 0 {
		t.Fatal("a drained box started box.unreachable")
	}
	// A box that dials while the service drains is sent on after hello.
	other := newBox(t)
	_, err = other.connect(s, nil)
	if code, reason := closeCode(err); code != cloudwire.CloseRestart || reason != "3000" {
		t.Fatalf("close %d %q (%v)", code, reason, err)
	}
}

// After a restart, an instance restores only the homes it holds.
func TestRestoreTakesOnlyThisShardsHomes(t *testing.T) {
	s := newService(t)
	mine, theirs := newBox(t), newBox(t)
	for _, b := range []*box{mine, theirs} {
		if _, err := b.connect(s, nil); err != nil {
			t.Fatal(err)
		}
		b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
		home := b.home
		wait(t, "the roster is stored", func() bool {
			h, ok, _ := s.reg.Get(home)
			return ok && h.Roster != nil
		})
	}
	up := New(s.store, s.reg, s.key, nil)
	up.Shards = twoShards(t, theirs.home)
	n, err := up.Restore()
	if err != nil || n != 1 {
		t.Fatalf("restored %d, %v", n, err)
	}
}

// stall makes home's box hang on every write while holding its write lock,
// as a socket the box stopped reading does once the kernel's buffers are
// full, until the test ends.
func stall(t *testing.T, s *service, home string) {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.up.mu.Lock()
	defer s.up.mu.Unlock()
	c := s.up.conns[home]
	if c == nil {
		t.Fatal("no box to stall")
	}
	c.write = func([]byte) error {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		<-release
		return errors.New("stalled")
	}
}

// A box that stops reading holds up only its own home: a phone of another
// home reaches its box at once while writes to the stuck one hang.
func TestAStuckBoxDoesNotHoldUpAnotherHome(t *testing.T) {
	s := newService(t)
	stuck := tunConnect(t, s)
	live := tunConnect(t, s)
	wait(t, "both boxes are their homes'", func() bool { return s.up.Boxes() == 2 })
	stall(t, s, stuck.home)
	got := make(chan struct{}, 64)
	go func() {
		for {
			if _, _, err := live.conn.ReadMessage(); err != nil {
				return
			}
			got <- struct{}{}
		}
	}()
	// A few phones of the stuck home, each hanging in its write.
	var blocked atomic.Int64
	for range 4 {
		go func() {
			blocked.Add(1)
			s.up.Tun(stuck.home, cloudwire.Tun{Dev: "owner", Sid: 1, D: []byte{1}})
			blocked.Add(-1)
		}()
	}
	wait(t, "the stuck home's phones hang", func() bool { return blocked.Load() == 4 })
	for i := range 10 {
		start := time.Now()
		if !s.up.Tun(live.home, cloudwire.Tun{Dev: "owner", Sid: 2, D: []byte{byte(i)}}) {
			t.Fatal("the live box is gone")
		}
		select {
		case <-got:
		case <-time.After(time.Second):
			t.Fatal("a tun for another home waited behind the stuck box")
		}
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("a tun for another home took %s", d)
		}
	}
	if blocked.Load() != 4 {
		t.Fatal("the stuck home's writes did not hang; the test proves nothing")
	}
}

// One box whose writes hang does not hold up the drain of the others: the
// close does not wait for the write lock.
func TestAStuckBoxDoesNotHoldUpTheDrain(t *testing.T) {
	s := newService(t)
	stuck := tunConnect(t, s)
	live := newBox(t)
	if _, err := live.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	wait(t, "both boxes are their homes'", func() bool { return s.up.Boxes() == 2 })
	stall(t, s, stuck.home)
	go s.up.Tun(stuck.home, cloudwire.Tun{Dev: "owner", Sid: 1, D: []byte{1}})
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	s.up.Drain("1000")
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the drain took %s", d)
	}
	_, _, err := live.conn.ReadMessage()
	if code, _ := closeCode(err); code != cloudwire.CloseRestart {
		t.Fatalf("the live box heard %v", err)
	}
	_, _, err = stuck.conn.ReadMessage()
	if code, _ := closeCode(err); code != cloudwire.CloseRestart {
		t.Fatalf("the stuck box heard %v", err)
	}
}
