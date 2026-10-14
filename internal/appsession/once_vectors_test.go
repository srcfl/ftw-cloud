package appsession

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// protocolTestdata is the testdata directory of the go/protocol this build
// pins, so the vectors move with the pin.
func protocolTestdata(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/srcfl/ftw/go/protocol").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "cloudwire", "testdata")
}

func readVectors(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(protocolTestdata(t), name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The service answers srcfl/ftw's cloud-once-vectors.json byte for byte: the
// same request, with the service's keys fixed as the vectors fix them and
// the home holding the envelopes of cloud-vectors.json, draws exactly the
// answer body the watch replays.
func TestOnceAnswersTheGoldenVectors(t *testing.T) {
	var once struct {
		ServiceStatic, ServiceEphemeral, WatchPublic string
		Home, Path, Request, Msg2Payload, Answer     string
		Held                                         []string
	}
	readVectors(t, "cloud-once-vectors.json", &once)
	var signed struct {
		Messages []struct {
			Name, T, Envelope string
		} `json:"messages"`
	}
	readVectors(t, "cloud-vectors.json", &signed)
	envelope := func(name string) []byte {
		for _, m := range signed.Messages {
			if m.Name == name {
				return unhex(t, m.Envelope)
			}
		}
		t.Fatalf("no signed vector %q", name)
		return nil
	}

	key, err := appwire.KeyPairFromSecret(unhex(t, once.ServiceStatic))
	if err != nil {
		t.Fatal(err)
	}
	eph, err := appwire.KeyPairFromSecret(unhex(t, once.ServiceEphemeral))
	if err != nil {
		t.Fatal(err)
	}
	// The service last heard from the box when message 2 says it did.
	var msg2 struct {
		LastSeenMs int64 `cbor:"lastSeenMs"`
	}
	env, err := cloudwire.DecodeEnvelope(unhex(t, once.Msg2Payload))
	if err != nil || cloudwire.Unmarshal(env.B, &msg2) != nil {
		t.Fatalf("message 2 payload: %v", err)
	}
	st := store.New(func() time.Time { return time.UnixMilli(msg2.LastSeenMs) })
	reg, err := registry.Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	box, _ := st.For(store.Principal{Kind: store.Box, Home: once.Home})
	box.Connected()
	box.SetRoster(&cloudwire.Roster{RosterSeq: 1, TTLS: 86_400,
		Devices: []cloudwire.Device{{ID: "watch", Key: unhex(t, once.WatchPublic), Role: "watch",
			Scopes: []string{protocol.ScopeLiveRead, protocol.ScopePlanRead, protocol.ScopeEventsRead}, Epoch: 1}},
		Grant: cloudwire.Grant{ID: make([]byte, 16), Scopes: []string{protocol.ScopeLiveRead},
			Purposes: []string{protocol.CloudPurposeServe}, Controller: cloudwire.ControllerSourceful}})
	for _, n := range []string{"live full", "live delta", "lp", "prices", "hb"} {
		raw := envelope(n)
		e, _ := cloudwire.DecodeEnvelope(raw)
		var hdr cloudwire.Header
		if err := cloudwire.Unmarshal(e.B, &hdr); err != nil {
			t.Fatal(err)
		}
		if err := box.Put(e.T, raw, hdr.Seq, n == "live full"); err != nil {
			t.Fatal(err)
		}
	}

	w := &watchCount{}
	app := New(st, reg, w, key, slog.New(slog.NewTextHandler(io.Discard, nil)))
	app.onceEphemeral = &eph
	// The vectors carry two envelopes in message 2 and one after it, as an
	// envelope that did not fit would follow. Bound message 2 the same way.
	two, _ := cloudwire.SnapshotPayload([][]byte{envelope("live delta"), envelope("prices")}, msg2.LastSeenMs, true, 1)
	app.onceMessage2 = len(two) + appwire.Message2Overhead
	srv := httptest.NewUnstartedServer(http.HandlerFunc(app.ServeOnce))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+once.Path, bytes.NewReader(unhex(t, once.Request)))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the vectors' request drew %d", resp.StatusCode)
	}
	if !bytes.Equal(body, unhex(t, once.Answer)) {
		t.Fatalf("the answer is not the vectors' bytes:\n got %x\nwant %s", body, once.Answer)
	}
	if w.count() != 1 {
		t.Fatalf("hz 1 asked the box %d times", w.count())
	}
	if len(once.Held) != 2 || once.Held[0] != "live full" || once.Held[1] != "lp" {
		t.Fatalf("the vectors' have covers %v; this test assumes the full live and the lp", once.Held)
	}
}
