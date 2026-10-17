package uplink

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Recovery needs the original box key from a private backup. A new box key
// must never get the old home's rights merely because someone names it.
func TestRecoveredBoxPurgesStatisticsWithoutAffectingAnotherHome(t *testing.T) {
	s := newService(t)
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	s.up.Statistics = true
	now := time.Now()
	original, other := newBox(t), newBox(t)
	for _, b := range []*box{original, other} {
		if _, err := b.connect(s, nil); err != nil {
			t.Fatal(err)
		}
		r := acceptedStatisticsRoster(b, now)
		b.send(cloudwire.MsgRoster, r)
		b.send(cloudwire.MsgStats, statisticsReport(b, r, now))
		b.send(cloudwire.MsgLive, cloudwire.Live{Header: b.header(), Fields: map[string]int64{"2": 1000}})
	}
	wait(t, "both reports stored", func() bool {
		for _, b := range []*box{original, other} {
			h, ok, _ := s.reg.Get(b.home)
			if !ok || h.RosterSeq != 1 || len(snapshot(t, s, b.home)) == 0 {
				return false
			}
		}
		v, _ := s.reg.StatisticsView(now)
		return v.Installations.State == "withheld"
	})
	backup, err := x509.MarshalECPrivateKey(original.key)
	if err != nil {
		t.Fatal(err)
	}
	_ = original.conn.Close()
	recovered := newBox(t)
	recovered.key, err = x509.ParseECPrivateKey(backup)
	if err != nil {
		t.Fatal(err)
	}
	recovered.pk, _ = cloudwire.PublicKeyBytesOf(&recovered.key.PublicKey)
	recovered.home = cloudwire.HomeID(recovered.pk)
	recovered.boot = bytes.Repeat([]byte{6}, 16)
	if _, err := recovered.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	recovered.send(cloudwire.MsgBye, cloudwire.Bye{Header: recovered.header(), Why: cloudwire.ByeRevoked, Purge: true})
	env := recovered.read()
	var receipt cloudwire.Purged
	if env.T != cloudwire.MsgPurged || cloudwire.Verify(&s.key.PublicKey, recovered.home, env) != nil ||
		cloudwire.Unmarshal(env.B, &receipt) != nil || receipt.What != cloudwire.PurgedHome {
		t.Fatal("recovery did not receive a signed home deletion receipt")
	}
	if _, ok, err := s.reg.Get(original.home); err != nil || ok {
		t.Fatal("recovered home remains", err)
	}
	if _, ok, err := s.reg.Get(other.home); err != nil || !ok {
		t.Fatal("another home was deleted", err)
	}
	v, err := s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "withheld" {
		t.Fatal("another home's report was deleted", err)
	}
	// Removing the other home's rows leaves no hidden rows from the recovery.
	if err := s.reg.Purge(other.home, nil, now); err != nil {
		t.Fatal(err)
	}
	v, err = s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "empty" {
		t.Fatal("recovered household hours remain", err)
	}
	_ = recovered.conn.Close()
	if _, err := recovered.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	recovered.send(cloudwire.MsgRoster, acceptedStatisticsRoster(recovered, now))
	if !recovered.closed() {
		t.Fatal("old backup resurrected a deleted home")
	}
}

func TestOfflineRightsErasureSurvivesCloudRestartAndBoxReconnect(t *testing.T) {
	s := newService(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.db")
	_ = s.reg.Close()
	var err error
	s.reg, err = registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.up.registry = s.reg
	if err := s.reg.StatisticsInit(); err != nil {
		t.Fatal(err)
	}
	s.up.Statistics = true
	now := time.Now()
	b := newBox(t)
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	r := acceptedStatisticsRoster(b, now)
	b.send(cloudwire.MsgRoster, r)
	b.send(cloudwire.MsgStats, statisticsReport(b, r, now))
	wait(t, "hour before the rights request", func() bool { v, _ := s.reg.StatisticsView(now); return v.Installations.State == "withheld" })
	_ = b.conn.Close()
	if err := s.reg.Close(); err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(dir, "verified-request.json")
	data, _ := json.Marshal(map[string]any{"case_id": "0af8aa77-b089-4250-865a-431384d0d39c", "home": b.home, "identity_checked": true, "verified_by": "test-operator", "verified_at": time.Now().UTC().Format(time.RFC3339)})
	if err := os.WriteFile(request, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("python3", "../../scripts/statistics-subject-request.py", "--database", path, "--request", request, "--erase").CombinedOutput(); err != nil {
		t.Fatalf("offline erasure: %v %s", err, out)
	}
	s.reg, err = registry.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.reg.Close()
	s.store = store.New(nil)
	s.up.registry, s.up.store = s.reg, s.store
	if n, err := s.up.Restore(); err != nil || n != 0 {
		t.Fatal("restricted Cloud copy restored", n, err)
	}
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	r.Header = b.header()
	r.RosterSeq++
	b.send(cloudwire.MsgRoster, r)
	if !b.closed() {
		t.Fatal("restricted home retained Cloud access")
	}
	if len(snapshot(t, s, b.home)) != 0 {
		t.Fatal("restricted home remained readable")
	}
	v, err := s.reg.StatisticsView(now)
	if err != nil || v.Installations.State != "empty" {
		t.Fatal("erased reports returned", err)
	}
	// The restriction must still allow the owner's full home deletion.
	if _, err := b.connect(s, nil); err != nil {
		t.Fatal(err)
	}
	b.send(cloudwire.MsgBye, cloudwire.Bye{Header: b.header(), Why: cloudwire.ByeRevoked, Purge: true})
	env := b.read()
	var receipt cloudwire.Purged
	if env.T != cloudwire.MsgPurged || cloudwire.Unmarshal(env.B, &receipt) != nil || receipt.What != cloudwire.PurgedHome {
		t.Fatal("restricted home could not be deleted")
	}
}
