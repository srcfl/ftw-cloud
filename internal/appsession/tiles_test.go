package appsession

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type tileVectorFile struct {
	BoxKey struct {
		D    string `json:"d"`
		Home string `json:"home"`
	} `json:"boxKey"`
	Tiles []struct {
		Name     string `json:"name"`
		TileID   string `json:"tileId"`
		Etag     string `json:"etag"`
		Envelope string `json:"envelope"`
	} `json:"tiles"`
	Have map[string][]string `json:"have"`
	Get  struct {
		Body string `json:"body"`
	} `json:"tilesGet"`
	End struct {
		Envelope string `json:"envelope"`
	} `json:"tilesEnd"`
}

// tileHarness is the harness on the vectors' box, at 17:16 on the vectors'
// day, with ftw.history.read in the grant and the vectors' tiles held.
func tileHarness(t *testing.T) (*harness, tileVectorFile) {
	t.Helper()
	var v tileVectorFile
	readVectors(t, "cloud-tile-vectors.json", &v)
	h := newHarness(t)
	h.shift.Store(int64(time.Until(time.UnixMilli(1_791_806_400_000 + (5*60+16)*60_000))))
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), unhex(t, v.BoxKey.D))
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	if err := h.reg.Claim(v.BoxKey.Home, pk, time.Now()); err != nil {
		t.Fatal(err)
	}
	box, err := h.store.For(storePrincipalBox(v.BoxKey.Home))
	if err != nil {
		t.Fatal(err)
	}
	box.Connected()
	h.boxKey, h.home, h.box = key, v.BoxKey.Home, box
	h.setRoster(h.devices(1, 1), protocol.ScopeLiveRead, protocol.ScopeHistoryRead)
	return h, v
}

// putTile holds one of the vectors' envelopes, as the uplink does once it
// has verified and checked it.
func (h *harness) putTile(t *testing.T, raw []byte) {
	t.Helper()
	env, err := cloudwire.DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cloudwire.Verify(&h.boxKey.PublicKey, h.home, env) != nil {
		t.Fatal("a vector does not verify")
	}
	var b cloudwire.Tiles
	if err := cloudwire.Unmarshal(env.B, &b); err != nil || b.Check() != nil {
		t.Fatalf("a vector is not a tile: %v", err)
	}
	if kept, _ := h.box.PutTile(raw, b); !kept {
		t.Fatal("a vector tile was not held")
	}
}

// tilesAnswer reads the answer to one tiles.get: the envelopes, then
// tiles.end, which it returns.
func (p *phone) tilesAnswer(t *testing.T) ([][]byte, cloudwire.TilesEnd) {
	t.Helper()
	var got [][]byte
	for {
		env, code := p.next(2 * time.Second)
		if code != 0 {
			t.Fatalf("closed with %d", code)
		}
		e, err := cloudwire.DecodeEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		if e.T == cloudwire.MsgTilesEnd {
			var end cloudwire.TilesEnd
			if len(e.Sig) != 0 || cloudwire.Unmarshal(e.B, &end) != nil {
				t.Fatal("tiles.end is not the service's own")
			}
			return got, end
		}
		got = append(got, env)
	}
}

func TestTilesGetAnswersWhatThePhoneLacksAsTheBoxSignedIt(t *testing.T) {
	h, v := tileHarness(t)
	for _, tv := range v.Tiles {
		h.putTile(t, unhex(t, tv.Envelope))
	}
	p := h.mustDial(dialOpts{key: h.owner, hz: 1})
	if len(p.snap.Envelopes) != 0 {
		t.Fatalf("message 2 carries %d envelopes", len(p.snap.Envelopes))
	}

	p.send(cloudwire.MsgTilesGet, cloudwire.TilesGet{})
	got, end := p.tilesAnswer(t)
	if end.N != 4 || len(got) != 4 {
		t.Fatalf("tiles.get {} answered %d, tiles.end says %d", len(got), end.N)
	}
	for i, tv := range v.Tiles {
		if !bytes.Equal(got[i], unhex(t, tv.Envelope)) {
			t.Fatalf("envelope %d (%s) is not the box's bytes", i, tv.Name)
		}
	}

	// The vectors' have holds the closed tile: the pieces come alone, as
	// the vectors say.
	var g cloudwire.TilesGet
	if err := cloudwire.Unmarshal(unhex(t, v.Get.Body), &g); err != nil {
		t.Fatal(err)
	}
	p.send(cloudwire.MsgTilesGet, g)
	got, end = p.tilesAnswer(t)
	if end.N != len(v.Have["answer"]) || len(got) != end.N {
		t.Fatalf("with have, %d envelopes and n %d", len(got), end.N)
	}
	for i, name := range v.Have["answer"] {
		if !bytes.Equal(got[i], unhex(t, v.Tiles[i+1].Envelope)) || v.Tiles[i+1].Name != name {
			t.Fatalf("answer %d is not %s", i, name)
		}
	}
}

func TestATileGoesToTheOwnersSessionAsItComesAndNotToAViewers(t *testing.T) {
	h, v := tileHarness(t)
	owner := h.mustDial(dialOpts{key: h.owner, hz: 1})
	viewer := h.mustDial(dialOpts{key: h.viewer, hz: 1})
	whole := unhex(t, v.Tiles[1].Envelope)
	h.putTile(t, whole)
	env, code := owner.next(2 * time.Second)
	if code != 0 || !bytes.Equal(env, whole) {
		t.Fatal("the owner did not get the tile as the box signed it")
	}
	// The viewer may not read history: tiles.get answers nothing, and the
	// tile never came.
	viewer.send(cloudwire.MsgTilesGet, cloudwire.TilesGet{})
	got, end := viewer.tilesAnswer(t)
	if len(got) != 0 || end.N != 0 {
		t.Fatalf("a viewer got %d tiles", len(got))
	}
}

// The box went away hours ago: no readings, but the tiles of the last 48
// hours still come, as the box dated them.
func TestTilesComeWhileTheBoxIsAway(t *testing.T) {
	h, v := tileHarness(t)
	h.live(true)
	for _, tv := range v.Tiles {
		h.putTile(t, unhex(t, tv.Envelope))
	}
	h.box.Disconnected(1)
	h.shift.Add(int64(3 * time.Hour))
	h.store.Sweep()
	p := h.mustDial(dialOpts{key: h.owner})
	if len(p.snap.Envelopes) != 0 || p.snap.Online {
		t.Fatalf("after three hours away the snapshot holds %d readings", len(p.snap.Envelopes))
	}
	p.send(cloudwire.MsgTilesGet, cloudwire.TilesGet{})
	if got, end := p.tilesAnswer(t); end.N != 4 || len(got) != 4 {
		t.Fatalf("away, tiles.get answered %d", len(got))
	}
}

// tiles.end is the bytes srcfl/ftw froze.
func TestTilesEndIsTheVector(t *testing.T) {
	var v tileVectorFile
	readVectors(t, "cloud-tile-vectors.json", &v)
	env, err := cloudwire.Unsigned(cloudwire.MsgTilesEnd, cloudwire.TilesEnd{N: 3})
	if err != nil || !bytes.Equal(env, unhex(t, v.End.Envelope)) {
		t.Fatal("tiles.end differs from the vector")
	}
}

func storePrincipalBox(home string) store.Principal {
	return store.Principal{Kind: store.Box, Home: home}
}
