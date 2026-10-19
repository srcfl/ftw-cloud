package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

// Core stays in its own module/process. Cloud still imports only the wire
// contract. CI checks out the exact paired Core commit and runs this test.
func TestMeasurementDiagnosticsAgainstRealCoreHandlers(t *testing.T) {
	core := os.Getenv("FTW_CORE_CHECKOUT")
	if core == "" {
		t.Skip("FTW_CORE_CHECKOUT is required for the paired Core integration")
	}
	binary := filepath.Join(t.TempDir(), "measurement-api")
	build := exec.Command("go", "build", "-race", "-o", binary, "./test/fixtures/measurement-api")
	build.Dir = filepath.Join(core, "go")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("Core measurement fixture failed to build: %s", output)
	}
	for _, mode := range []string{"missing", "disabled", "repaired"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(binary, mode)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal("could not create fixture input")
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal("could not create fixture output")
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if cmd.Start() != nil {
				t.Fatal("could not start Core measurement fixture")
			}
			t.Cleanup(func() {
				_ = stdin.Close()
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				select {
				case err := <-done:
					if err != nil {
						t.Error("Core measurement fixture exited with an error")
					}
				case <-time.After(10 * time.Second):
					_ = cmd.Process.Kill()
					<-done
					t.Error("Core measurement fixture did not stop")
				}
			})
			ready := make(chan string, 1)
			go func() {
				reader := bufio.NewReader(stdout)
				line, _ := reader.ReadString('\n')
				ready <- strings.TrimSpace(line)
			}()
			var base string
			select {
			case base = <-ready:
			case <-time.After(30 * time.Second):
				t.Fatal("Core measurement fixture did not start")
			}
			u, err := url.Parse(base)
			if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" {
				t.Fatal("Core measurement fixture returned no local endpoint")
			}
			client := &http.Client{Timeout: 5 * time.Second}
			read := func(q protocol.APIRead) (int, []byte) {
				values := url.Values{}
				for k, v := range q.Query {
					values.Set(k, v)
				}
				resp, err := client.Get(base + q.Path + "?" + values.Encode())
				if err != nil {
					return 503, nil
				}
				defer resp.Body.Close()
				data, _ := io.ReadAll(io.LimitReader(resp.Body, protocol.AgentAPIMaxBytes))
				return resp.StatusCode, data
			}
			w := newWorld(t)
			box := w.connectBox()
			box.mu.Lock()
			box.apiReply = read
			box.mu.Unlock()
			assistant := w.connect(box, oauth.ScopeDiagRun)
			data, text := measurementResult(t, assistant, "status", nil)
			for _, name := range []string{"charger-current", "charger-old", "garage", "fixture-device", "fixture-site"} {
				if strings.Contains(text, name) {
					t.Fatal("a real Core private identifier escaped MCP")
				}
			}
			status, body := read(protocol.APIRead{Path: "/api/status"})
			var local struct {
				Body map[string]any `json:"body"`
			}
			if status != 200 || json.Unmarshal(body, &local) != nil {
				t.Fatal("Core status was unavailable")
			}
			if data["load_w"] != local.Body["load_w"] || data["history_quality"] != local.Body["history_quality"] {
				t.Fatal("MCP changed Core's measurement value or quality")
			}
			connection := data["charger_connections"].([]any)[0].(map[string]any)
			if mode == "repaired" {
				if data["load_w"] != float64(3000) || connection["status"] != "configured" {
					t.Fatal("explicit repair with fresh power did not qualify")
				}
				estimate := data["load_estimate"].(map[string]any)
				localEstimate := local.Body["load_estimate"].(map[string]any)
				if estimate["watts"] != nil || estimate["reason"] != localEstimate["reason"] || estimate["reason"] != "incomplete_source_window" {
					t.Fatal("missing interval coverage was hidden by good live power")
				}
			} else {
				if data["load_w"] != nil || connection["status"] != mode || data["history_reason"] != "missing:"+connection["source_id"].(string)+":ev" {
					t.Fatal("MCP lost Core's missing EV reason and binding association")
				}
				localReason, _ := local.Body["history_reason"].(string)
				if !strings.HasPrefix(localReason, "missing:") || !strings.HasSuffix(localReason, ":ev") {
					t.Fatal("the real Core did not produce the expected missing EV reason")
				}
			}
			assets, _ := measurementResult(t, assistant, "assets", nil)
			asset := assets["assets"].([]any)[0].(map[string]any)["asset_id"]
			args := measurementWindow()
			args["asset_id"] = asset
			energy, _ := measurementResult(t, assistant, "energy", args)
			found := false
			for _, row := range energy["points"].([]any) {
				p := row.(map[string]any)
				if p["quality"] == "measured" && p["energy_wh"] == float64(12) && p["provenance"] == "counter" && p["sample_count"] == float64(1) {
					found = true
				}
			}
			if !found {
				t.Fatal("real SQLite energy provenance did not reach MCP")
			}
			catalog, _ := measurementResult(t, assistant, "series_catalog", nil)
			args = measurementWindow()
			args["source_id"] = catalog["source_ids"].([]any)[0]
			args["metric_id"] = catalog["metrics"].([]any)[0].(map[string]any)["metric_id"]
			series, _ := measurementResult(t, assistant, "series", args)
			if len(series["points"].([]any)) == 0 {
				t.Fatal("real SQLite source observations did not reach MCP")
			}
		})
	}
}
