package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/ops"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// An hour of the service's counts, over a box on QUIC and a phone on a
// WebSocket that send a command through the tunnel, holds the traffic and
// names no home, device, key or address. Its fields are the series the
// service had before the traffic: none is made for a home.
func TestAnHourOfCountsNamesNobody(t *testing.T) {
	s := newStack(t)
	svc, err := ops.New(s.reg, "", "s1")
	if err != nil {
		t.Fatal(err)
	}
	before := &held{}
	metrics.Default.NewKeeper(before, nil).Close()
	keeper := metrics.Default.NewKeeper(svc, func(err error) { t.Error(err) })

	box := s.connectTunBoxQUIC()
	key, _ := appwire.GenerateKeyPair()
	box.roster(2, grantOff, nil, key.Public())
	var phone *tunPhone
	eventually(t, "the phone is admitted", func() bool {
		phone = s.dialPhone(box.home, key, cloudwire.Now{Hz: cloudwire.HzLooking}, "")
		return phone.conn != nil && phone.tr != nil
	})
	phone.open(box.static.Public(), 7, nil)
	if ack, res := phone.cmd(7, "0192f2a0-7c1e-7000-8000-0000000000a0"); ack != protocol.MsgCmdAck || res != protocol.CmdApplied {
		t.Fatalf("ack %q, result %q", ack, res)
	}
	keeper.Close()

	rows, err := s.reg.OpsHours(0, math.MaxInt64, 10)
	if err != nil || len(rows) == 0 {
		t.Fatalf("%d hours, %v", len(rows), err)
	}
	var h metrics.Hour
	if err := json.Unmarshal(rows[len(rows)-1], &h); err != nil {
		t.Fatal(err)
	}
	if h.Counters["tun_frames_up"] == 0 || h.Counters["tun_frames_down"] == 0 || h.Histograms["handshake_seconds_box"] == nil {
		t.Fatalf("the hour missed the traffic: %v", h.Counters)
	}
	if g := h.Gauges["transport_sockets_box_quic"]; g.N == 0 {
		t.Fatalf("no box over QUIC in the hour: %v", h.Gauges)
	}
	boxKey, _ := cloudwire.PublicKeyBytesOf(&box.key.PublicKey)
	for _, row := range rows {
		for _, needle := range []string{box.home, cloudwire.DeviceID(key.Public()), base64.RawURLEncoding.EncodeToString(boxKey),
			base64.RawURLEncoding.EncodeToString(key.Public()), base64.RawURLEncoding.EncodeToString(box.static.Public()), "127.0.0.1", "::1"} {
			if bytes.Contains(row, []byte(needle)) {
				t.Fatalf("an hour holds %q: %s", needle, row)
			}
		}
	}
	for name, fields := range map[string][]string{
		"counters":   slices.Sorted(maps.Keys(h.Counters)),
		"gauges":     slices.Sorted(maps.Keys(h.Gauges)),
		"histograms": slices.Sorted(maps.Keys(h.Histograms)),
	} {
		var want []string
		switch name {
		case "counters":
			want = slices.Sorted(maps.Keys(before.got.Counters))
		case "gauges":
			want = slices.Sorted(maps.Keys(before.got.Gauges))
		default:
			want = slices.Sorted(maps.Keys(before.got.Histograms))
		}
		if !slices.Equal(fields, want) {
			t.Fatalf("%s changed with the traffic: %v, before %v", name, fields, want)
		}
	}
}

type held struct{ got metrics.Hour }

func (h *held) PutHour(x metrics.Hour) error {
	h.got = x
	return nil
}
