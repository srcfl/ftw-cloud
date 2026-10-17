package uplink

import (
	"bytes"

	"github.com/srcfl/ftw-cloud/internal/store"
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
	r.Grant.TermsPolicy = cloudwire.CloudTermsPolicy
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
	r.Grant.TermsPolicy = cloudwire.CloudTermsPolicy
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

func TestLocalStatisticsAcceptsHoursWithoutRemoteRecipients(t *testing.T) {
	s := newService(t)
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	s.up.Statistics = true
	now := time.Now()
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	r := b.roster()
	r.Devices = nil
	r.Grant.Purposes = []string{protocol.CloudPurposeStats}
	r.Grant.TermsPolicy, r.Grant.StatsPolicy = cloudwire.StatsPolicy, cloudwire.StatsPolicy
	r.Grant.StatsID = bytes.Repeat([]byte{7}, 16)
	r.Grant.StatsSinceMs = now.Add(-2 * time.Hour).UnixMilli()
	b.send(cloudwire.MsgRoster, r)
	report := cloudwire.Stats{Header: b.header(), StatsID: r.Grant.StatsID, Policy: cloudwire.StatsPolicy, HourMS: now.Truncate(time.Hour).Add(-time.Hour).UnixMilli(), Metrics: map[string]int64{"pv_generation_wh": 120}}
	b.send(cloudwire.MsgStats, report)
	wait(t, "local statistics hour", func() bool {
		v, err := s.reg.StatisticsView(now)
		return err == nil && v.Installations.State == "withheld"
	})
	if _, err := s.store.For(store.Principal{Kind: store.Device, Home: b.home, DeviceKey: ownerKey}); err == nil {
		t.Fatal("local statistics admitted a phone")
	}
}

func TestStatisticsOnlyRejectsRemoteMetadata(t *testing.T) {
	b := newBox(t)
	r := b.roster()
	r.Devices = nil
	r.Grant.Purposes = []string{protocol.CloudPurposeStats}
	r.Grant.TermsPolicy, r.Grant.StatsPolicy = cloudwire.StatsPolicy, cloudwire.StatsPolicy
	r.Grant.StatsID = make([]byte, 16)
	if !statisticsOnly(r) {
		t.Fatal("valid local roster refused")
	}
	r.Noise = make([]byte, 32)
	if statisticsAccess(r) {
		t.Fatal("statistics-only exposed a Noise key")
	}
	r.Noise = nil
	r.Devices = b.roster().Devices
	if statisticsAccess(r) {
		t.Fatal("statistics-only exposed phone recipients")
	}
}

func TestActivatingStatisticsRejectsLegacyCloudAndStoredRoster(t *testing.T) {
	s := newService(t)
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgRoster, b.roster(protocol.ScopeLiveRead))
	b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1200}})
	wait(t, "legacy cache", func() bool { return len(snapshot(t, s, b.home)) > 0 })
	// Restart into a fresh in-memory store: the disk roster must not grant
	// old Cloud access after the new terms become mandatory.
	fresh := New(store.New(nil), s.reg, s.key, s.up.log)
	fresh.Statistics = true
	n, err := fresh.Restore()
	if err != nil || n != 0 {
		t.Fatal("legacy roster survived terms activation", n, err)
	}
	approved := newService(t)
	if err := approved.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	approved.up.Statistics = true
	next := newBox(t)
	if _, err := next.connect(approved, nil); err != nil {
		t.Fatal(err)
	}
	r := next.roster(protocol.ScopeLiveRead)
	next.send(cloudwire.MsgRoster, r)
	if !next.closed() {
		t.Fatal("legacy Cloud stayed connected without current terms")
	}
	if len(snapshot(t, approved, next.home)) > 0 {
		t.Fatal("legacy cache remained readable")
	}
}
