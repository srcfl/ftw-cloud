package uplink

import (
	"bytes"
	"testing"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// The car class is held like the other copy classes, as the box signed it,
// and a phone reads it only under ftw.live.read (docs/protocol-cloud.md,
// "car").
func TestTheCarClassIsHeldAndServedUnderLive(t *testing.T) {
	soc, age := int64(640), int64(120)
	car := cloudwire.Cars{Cars: []cloudwire.Car{{ID: "c4R1d0x9", SocPermille: &soc, SocSource: protocol.CarSoCVehicle,
		SocAgeS: &age, EnergySinceWh: 300, Goal: &cloudwire.CarGoal{TargetPermille: 800, ReadyByMin: 420, Days: 0x7f}}}}
	for _, c := range []struct {
		name   string
		scopes []string
		served bool
	}{
		{"live granted", []string{protocol.ScopeLiveRead}, true},
		{"live not granted", []string{protocol.ScopeEventsRead}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newService(t)
			b := newBox(t)
			if _, err := b.connect(s, nil); err != nil {
				t.Fatal(err)
			}
			b.send(cloudwire.MsgRoster, b.roster(c.scopes...))
			c2 := car
			c2.Header = b.header()
			sent := b.send(cloudwire.MsgCar, c2)
			hb := b.send(cloudwire.MsgHB, cloudwire.HB{Header: b.header(), Clock: cloudwire.ClockNTP})
			wait(t, "the hb", func() bool {
				for _, e := range snapshot(t, s, b.home) {
					if bytes.Equal(e, hb) {
						return true
					}
				}
				return false
			})
			got := snapshot(t, s, b.home)
			held := false
			for _, e := range got {
				held = held || bytes.Equal(e, sent)
			}
			if held != c.served {
				t.Fatalf("car served %v, want %v (%d envelopes)", held, c.served, len(got))
			}
			if b.closed() {
				t.Fatal("the car class closed the uplink")
			}
		})
	}
}
