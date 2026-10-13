package appsession

import (
	"slices"
	"testing"
	"time"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// A home the size of a real one: the source table, a live, an lp with one
// car, a day and a half of quarter-hour prices and an hb.
func (h *harness) fillLikeAHouse() {
	srcs := map[string]cloudwire.Source{}
	ages := map[string]int64{}
	for _, id := range []string{"ACfHt4DWL7g", "f-oHMDqV-mA", "DUYWWQmn-Xg", "j3HZORNCWHs"} {
		srcs[id] = cloudwire.Source{Kind: "driver", State: protocol.SourceLive, LastOkMs: 59_000, StaleAfterMs: 10_000}
		ages[id] = 900
	}
	fields := map[string]int64{"1": 0, "2": 1840, "3": -2310, "4": 950, "5": 612, "6": 1100, "10": 2100}
	h.put(cloudwire.MsgLive, func(hdr cloudwire.Header) any {
		return cloudwire.Live{Header: hdr, Fields: fields, Sources: srcs, SrcRev: 1, Ages: ages,
			FieldSources: map[string][]string{"2": {"ACfHt4DWL7g"}, "3": {"f-oHMDqV-mA"}, "10": {"DUYWWQmn-Xg"}}}
	}, true)
	h.put(cloudwire.MsgLive, func(hdr cloudwire.Header) any {
		return cloudwire.Live{Header: hdr, Fields: fields, SrcRev: 1, Ages: ages}
	}, false)
	v := func(x int64) *int64 { return &x }
	h.put(cloudwire.MsgLP, func(hdr cloudwire.Header) any {
		return cloudwire.LP{Header: hdr, ControlRev: 812, Loadpoints: []cloudwire.Loadpoint{{
			ID: "j3HZORNCWHs", Src: "DUYWWQmn-Xg", Plugged: true, SocPermille: v(430), SocSource: "inferred",
			TargetPermille: v(800), ReadyByMs: v(1_791_867_600_000), PowerW: 2100, SessionWh: 3400, Session: "s1",
			CommandedW: v(2070), CommandedReason: "plan", NextStartMs: v(1_791_850_000_000)}},
			Feedback: []cloudwire.Feedback{{Kind: "ev", Src: "DUYWWQmn-Xg", Status: "following", Reason: "plan",
				Severity: "ok", Evidence: "measured", Fresh: true, ActualW: v(2100), AgeMs: v(900)}}}
	}, false)
	var spot, total []*int64
	for i := range 144 {
		spot, total = append(spot, v(int64(40+i%30))), append(total, v(int64(110+i%30)))
	}
	h.put(cloudwire.MsgPrices, func(hdr cloudwire.Header) any {
		return cloudwire.Prices{Header: hdr, Zone: "SE3", Currency: "SEK", T0Ms: 1_791_820_800_000, SlotMs: 900_000,
			SpotMinor: spot, TotalMinor: total}
	}, false)
	h.put(cloudwire.MsgHB, func(hdr cloudwire.Header) any {
		return cloudwire.HB{Header: hdr, Clock: cloudwire.ClockNTP, SrcRev: 1, LiveSeq: 2, LpSeq: 3, Ages: ages}
	}, false)
}

// The doc's speed claim for the second layer: the cloud's copy, from memory,
// in well under 100 ms. Here the whole of it on loopback: TCP, TLS 1.3, the
// WebSocket upgrade, Noise IK and the snapshot, twenty times.
func TestTheSnapshotArrivesFast(t *testing.T) {
	h := newHarness(t)
	h.fillLikeAHouse()
	var took []time.Duration
	var size int
	for range 20 {
		start := time.Now()
		p := h.mustDial(dialOpts{key: h.owner, hz: 1})
		took = append(took, time.Since(start))
		size = len(p.snap.Envelopes)
		p.conn.Close()
	}
	slices.Sort(took)
	p50, p95 := took[len(took)/2], took[len(took)*95/100]
	t.Logf("handshake and snapshot of %d envelopes on loopback: p50 %v, p95 %v, max %v", size, p50, p95, took[len(took)-1])
	if p95 > 100*time.Millisecond {
		t.Fatalf("p95 %v is over the 100 ms the snapshot has", p95)
	}
}

// What the service spends per phone between message 1 and message 2: the
// store's snapshot, the payload and the Noise work, with no network.
func BenchmarkSnapshot(b *testing.B) {
	h := newHarness(b)
	h.fillLikeAHouse()
	now, _ := cloudwire.Unsigned(cloudwire.MsgNow, cloudwire.Now{Hz: 1})
	prologue := cloudwire.AppPrologue(h.home)
	b.ReportAllocs()
	var bytesOut int
	for b.Loop() {
		init, _ := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: h.owner, RemoteStatic: h.noise.Public(), Prologue: prologue})
		msg1, _ := init.WriteMessage(now)
		resp, _ := appwire.NewResponder(appwire.HandshakeOptions{StaticKey: h.noise, Prologue: prologue})
		if _, err := resp.ReadMessage(msg1); err != nil {
			b.Fatal(err)
		}
		dev, err := h.store.For(storePrincipal(h, h.owner))
		if err != nil {
			b.Fatal(err)
		}
		snap, sess, err := dev.Open()
		if err != nil {
			b.Fatal(err)
		}
		payload, _, err := snapshotPayload(snap)
		if err != nil {
			b.Fatal(err)
		}
		msg2, err := resp.WriteMessage(payload)
		if err != nil {
			b.Fatal(err)
		}
		sess.Close()
		bytesOut = len(msg2)
	}
	b.ReportMetric(float64(bytesOut), "msg2-bytes")
}
