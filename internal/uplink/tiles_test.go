package uplink

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// tileVectors is srcfl/ftw's cloud-tile-vectors.json, from the go/protocol
// this build pins.
type tileVectors struct {
	BoxKey struct {
		D    string `json:"d"`
		PK   string `json:"pk"`
		Home string `json:"home"`
	} `json:"boxKey"`
	Tiles []struct {
		Name     string `json:"name"`
		TileID   string `json:"tileId"`
		Etag     string `json:"etag"`
		Partial  bool   `json:"partial"`
		Envelope string `json:"envelope"`
		Frame    string `json:"frame"`
	} `json:"tiles"`
	Forged struct {
		Frame string `json:"frame"`
	} `json:"forged"`
}

func readTileVectors(t *testing.T) tileVectors {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/srcfl/ftw/go/protocol").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(out)), "cloudwire", "testdata", "cloud-tile-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v tileVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// vectorClock is 2026-10-12 17:16 UTC, when the vectors' last append had
// gone.
var vectorClock = time.UnixMilli(1_791_806_400_000 + (5*60+16)*60_000)

// newServiceAt is newService with the store on a clock of its own.
func newServiceAt(t *testing.T, now func() time.Time) *service {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	st := store.New(now)
	up := New(st, reg, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srv := httptest.NewUnstartedServer(up)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &service{srv: srv, up: up, store: st, reg: reg, key: key}
}

// vectorBox is the box that signed the vectors.
func vectorBox(t *testing.T, v tileVectors) *box {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), unhex(t, v.BoxKey.D))
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	if cloudwire.HomeID(pk) != v.BoxKey.Home {
		t.Fatal("the vectors' home is not their key's")
	}
	return &box{t: t, key: key, pk: pk, home: v.BoxKey.Home, boot: bytes.Repeat([]byte{0xb0}, 16), seq: 100}
}

func (b *box) frame(raw []byte) {
	b.t.Helper()
	if err := b.conn.WriteMessage(websocket.BinaryMessage, raw); err != nil {
		b.t.Fatal(err)
	}
}

func ownerTiles(t *testing.T, s *service, home string) [][]byte {
	t.Helper()
	dev, err := s.store.For(store.Principal{Kind: store.Device, Home: home, DeviceKey: ownerKey})
	if err != nil {
		return nil
	}
	got, _ := dev.Tiles(nil)
	return got
}

// The service holds the tiles the box signed, exactly, names the closed one
// in hello_ok when the box comes back, and serves them after the box left.
func TestTheServiceHoldsTheBoxsTilesAndNamesTheClosedOnesAtReconnect(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	ok, err := b.connect(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ok.Have) != 0 {
		t.Fatalf("a new home's have is %v", ok.Have)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeHistoryRead))
	var want [][]byte
	for _, tv := range v.Tiles {
		b.frame(unhex(t, tv.Frame))
		want = append(want, unhex(t, tv.Envelope))
	}
	wait(t, "four tiles", func() bool { return len(ownerTiles(t, s, b.home)) == 4 })
	for i, got := range ownerTiles(t, s, b.home) {
		if !bytes.Equal(got, want[i]) {
			t.Fatalf("tile %d is not the box's bytes", i)
		}
	}

	_ = b.conn.Close()
	wait(t, "the box gone", func() bool { return s.up.Boxes() == 0 })
	ok, err = b.connect(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ok.Have) != 1 || ok.Have[v.Tiles[0].TileID] != v.Tiles[0].Etag {
		t.Fatalf("hello_ok.have %v, want the closed tile alone", ok.Have)
	}
}

// A tile the box did not sign closes the uplink, as any such message does,
// and is never held.
func TestAForgedTileClosesTheUplinkAndIsNeverHeld(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeHistoryRead))
	b.frame(unhex(t, v.Forged.Frame))
	if !b.closed() {
		t.Fatal("the service kept the uplink after a forged tile")
	}
	if got := ownerTiles(t, s, b.home); len(got) != 0 {
		t.Fatalf("%d tiles held", len(got))
	}
	// Nor one signed by another key.
	b2 := vectorBox(t, v)
	if _, err := b2.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var body cloudwire.Tiles
	env, _ := cloudwire.DecodeEnvelope(unhex(t, v.Tiles[1].Envelope))
	_ = cloudwire.Unmarshal(env.B, &body)
	b2.sendAs(other, cloudwire.MsgTiles, body)
	if !b2.closed() || len(ownerTiles(t, s, b2.home)) != 0 {
		t.Fatal("a tile under another key was held")
	}
}

// A tile the box signed that is not one of the three shapes is dropped and
// counted; the uplink and the rest of the copy go on.
func TestATileOfNoShapeIsDroppedAndTheUplinkStays(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeHistoryRead))
	env, _ := cloudwire.DecodeEnvelope(unhex(t, v.Tiles[2].Envelope))
	var body cloudwire.Tiles
	_ = cloudwire.Unmarshal(env.B, &body)
	body.Header = b.header()
	body.Etag = "00000000"
	b.send(cloudwire.MsgTiles, body)
	live := b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1200},
		Sources: map[string]cloudwire.Source{"x": {Kind: "driver", State: "live", StaleAfterMs: 10_000}}, SrcRev: 1})
	wait(t, "the live after it", func() bool {
		snap := snapshot(t, s, b.home)
		return len(snap) == 1 && bytes.Equal(snap[0], live)
	})
	if got := ownerTiles(t, s, b.home); len(got) != 0 {
		t.Fatalf("a tile of no shape was held")
	}
}

// Without ftw.history.read in the grant the service holds no tiles.
func TestTilesNeedTheHistoryScopeInTheGrant(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	for _, tv := range v.Tiles {
		b.frame(unhex(t, tv.Frame))
	}
	live := b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1}, SrcRev: 1})
	wait(t, "the live after the tiles", func() bool {
		snap := snapshot(t, s, b.home)
		return len(snap) == 1 && bytes.Equal(snap[0], live)
	})
	dev, err := s.store.For(store.Principal{Kind: store.Box, Home: b.home})
	if err != nil {
		t.Fatal(err)
	}
	if have := dev.TilesHave(); len(have) != 0 || s.store.TileBytes() != 0 {
		t.Fatalf("held %v under a grant without history", have)
	}
}

// A tiles envelope over cloudwire.TileEnvelopeMax is dropped, signed or not,
// and the uplink goes on.
func TestAnOversizedTileIsDroppedAndTheUplinkStays(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead, protocol.ScopeHistoryRead))
	env, _ := cloudwire.DecodeEnvelope(unhex(t, v.Tiles[0].Envelope))
	var body cloudwire.Tiles
	_ = cloudwire.Unmarshal(env.B, &body)
	// The closed tile with a key the service ignores, to pad it.
	padded := struct {
		cloudwire.Tiles
		Pad []byte `cbor:"pad"`
	}{body, bytes.Repeat([]byte{1}, cloudwire.TileEnvelopeMax)}
	padded.Header = b.header()
	b.send(cloudwire.MsgTiles, padded)
	live := b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1}, SrcRev: 1})
	wait(t, "the live after it", func() bool {
		snap := snapshot(t, s, b.home)
		return len(snap) == 1 && bytes.Equal(snap[0], live)
	})
	if got := ownerTiles(t, s, b.home); len(got) != 0 {
		t.Fatal("an oversized tile was held")
	}
}

// History taken out of the grant and put back while the box stays
// connected: the service dropped the tiles, so it asks the box for them
// again, once.
func TestHistoryBackInTheGrantAsksTheBoxForItsTiles(t *testing.T) {
	v := readTileVectors(t)
	s := newServiceAt(t, func() time.Time { return vectorClock })
	b := vectorBox(t, v)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	roster := func(seq uint64, scopes ...string) {
		r := b.roster(scopes...)
		r.RosterSeq = seq
		b.send(cloudwire.MsgRoster, r)
	}
	roster(1, protocol.ScopeLiveRead, protocol.ScopeHistoryRead)
	b.frame(unhex(t, v.Tiles[0].Frame))
	wait(t, "the tile", func() bool { return len(ownerTiles(t, s, b.home)) == 1 })

	roster(2, protocol.ScopeLiveRead)
	roster(3, protocol.ScopeLiveRead, protocol.ScopeHistoryRead)
	b.send(cloudwire.MsgHB, cloudwire.HB{Header: b.header(), Clock: cloudwire.ClockNTP})
	env := b.read()
	var r cloudwire.Resync
	if env.T != cloudwire.MsgResync || cloudwire.Unmarshal(env.B, &r) != nil || len(r.What) != 1 || r.What[0] != cloudwire.ResyncTiles {
		t.Fatalf("the service sent %q, want resync for tiles", env.T)
	}
	// Not again within five minutes.
	roster(4, protocol.ScopeLiveRead)
	roster(5, protocol.ScopeLiveRead, protocol.ScopeHistoryRead)
	b.send(cloudwire.MsgHB, cloudwire.HB{Header: b.header(), Clock: cloudwire.ClockNTP})
	_ = b.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := b.conn.ReadMessage(); err == nil {
		t.Fatal("a second resync within five minutes")
	}
}
