package uplink

import (
	"bytes"

	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
	"testing"
	"time"
)

func TestSignedStatisticsRequireCurrentConsentAndNeverForward(t *testing.T) {
	s := newService(t)
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	s.up.Statistics = true
	now := time.Now()
	b := newBox(t)
	if ok, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	} else if ok.StatsPolicy != cloudwire.StatsPolicy {
		t.Fatal("approved policy not advertised")
	}
	r := b.roster(protocol.ScopeLiveRead)
	r.Grant.Purposes = append(r.Grant.Purposes, protocol.CloudPurposeStats)
	r.Grant.StatsID = bytes.Repeat([]byte{9}, 16)
	r.Grant.StatsPolicy = cloudwire.StatsPolicy
	r.Grant.StatsSinceMs = now.Add(-2 * time.Hour).UnixMilli()
	b.send(cloudwire.MsgRoster, r)
	report := cloudwire.Stats{Header: b.header(), StatsID: r.Grant.StatsID, Policy: cloudwire.StatsPolicy, HourMS: now.Truncate(time.Hour).Add(-time.Hour).UnixMilli(), Metrics: map[string]int64{"pv_generation_wh": 120}}
	b.send(cloudwire.MsgStats, report)
	wait(t, "statistics accepted", func() bool {
		v, err := s.reg.StatisticsView(now)
		return err == nil && v.Installations.State == "withheld"
	})
	for _, raw := range snapshot(t, s, b.home) {
		env, err := cloudwire.DecodeEnvelope(raw)
		if err != nil {
			t.Fatal(err)
		}
		if env.T == cloudwire.MsgStats {
			t.Fatal("statistics reached phone")
		}
	}
	r.Header = b.header()
	r.RosterSeq++
	r.Grant.Purposes = []string{protocol.CloudPurposeServe}
	r.Grant.StatsID = nil
	r.Grant.StatsPolicy = ""
	r.Grant.StatsSinceMs = 0
	b.send(cloudwire.MsgRoster, r)
	wait(t, "withdrawal deleted rows", func() bool {
		v, err := s.reg.StatisticsView(now)
		return err == nil && v.Installations.State == "empty"
	})
	report.Header = b.header()
	b.send(cloudwire.MsgStats, report)
	// A following live frame proves the service processed the stale stats.
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1200}})
	wait(t, "following live frame", func() bool { return len(snapshot(t, s, b.home)) > 0 })
	v, err := s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "empty" {
		t.Fatal("stale consent restored rows")
	}
}

func TestPausedStatisticsIgnoreReportsButStillDeleteOnWithdrawal(t *testing.T) {
	s := newService(t)
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	s.up.StatisticsStore = true
	now := time.Now()
	b := newBox(t)
	ok, err := b.connect(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ok.StatsPolicy != "" {
		t.Fatal("paused service advertised a policy")
	}
	r := b.roster(protocol.ScopeLiveRead)
	r.Grant.Purposes = append(r.Grant.Purposes, protocol.CloudPurposeStats)
	r.Grant.StatsID = bytes.Repeat([]byte{9}, 16)
	r.Grant.StatsPolicy = cloudwire.StatsPolicy
	r.Grant.StatsSinceMs = now.Add(-2 * time.Hour).UnixMilli()
	b.send(cloudwire.MsgRoster, r)
	report := cloudwire.Stats{Header: b.header(), StatsID: r.Grant.StatsID, Policy: cloudwire.StatsPolicy, HourMS: now.Truncate(time.Hour).Add(-time.Hour).UnixMilli(), Metrics: map[string]int64{"pv_generation_wh": 120}}
	b.send(cloudwire.MsgStats, report)
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1200}})
	wait(t, "paused report processed", func() bool { return len(snapshot(t, s, b.home)) > 0 })
	v, err := s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "empty" {
		t.Fatal("paused service stored a report")
	}
	// A row from before the pause must still be erased by the next roster.
	if err := s.reg.StatisticsPut(b.home, report, now); err != nil {
		t.Fatal(err)
	}
	v, err = s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "withheld" {
		t.Fatal("fixture did not store the earlier row")
	}
	r.Header = b.header()
	r.RosterSeq++
	r.Grant.Purposes = []string{protocol.CloudPurposeServe}
	r.Grant.StatsID = nil
	r.Grant.StatsPolicy = ""
	r.Grant.StatsSinceMs = 0
	b.send(cloudwire.MsgRoster, r)
	wait(t, "paused service erased withdrawn rows", func() bool {
		v, err := s.reg.StatisticsView(now)
		return err == nil && v.Installations.State == "empty"
	})
}
