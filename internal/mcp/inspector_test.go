package mcp

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A smoke test with the official MCP inspector's CLI against the whole path:
// a real token, the stub box, tools/list and tools/call. It runs when
// MCP_INSPECTOR names the command, for example
//
//	MCP_INSPECTOR="npx -y @modelcontextprotocol/inspector@2.3.0" go test -run Inspector ./internal/mcp
//
// and is skipped otherwise, so the suite needs no Node.
func TestInspectorSmoke(t *testing.T) {
	cmdline := strings.Fields(os.Getenv("MCP_INSPECTOR"))
	if len(cmdline) == 0 {
		t.Skip("MCP_INSPECTOR is not set")
	}
	w := newWorld(t)
	b := w.connectBox()
	a := w.connect(b, "")

	// Node trusts the test server's certificate through this file only.
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) map[string]any {
		t.Helper()
		full := append(append(append([]string{}, cmdline[1:]...), "--cli", w.srv.URL+Path, "--transport", "http",
			"--header", "Authorization: Bearer "+a.token, "--format", "json"), args...)
		cmd := exec.Command(cmdline[0], full...)
		cmd.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+ca, "MCP_CATALOG_PATH="+filepath.Join(t.TempDir(), "mcp.json"),
			"MCP_CLIENT_CONFIG_PATH="+filepath.Join(t.TempDir(), "client.json"))
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("inspector %v: %v\n%s\n%s", args, err, out.String(), errb.String())
			}
		case <-time.After(90 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("inspector %v timed out\n%s", args, errb.String())
		}
		var v struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Result == nil {
			t.Fatalf("inspector %v printed no result: %v\n%s\n%s", args, err, out.String(), errb.String())
		}
		return v.Result
	}

	list := run("--method", "tools/list")
	tools, _ := list["tools"].([]any)
	if len(tools) < 14 {
		t.Fatalf("tools/list through the inspector: %v", list)
	}
	call := run("--method", "tools/call", "--tool-name", "status")
	if call["isError"] == true || !strings.Contains(toJSON(call), "IGNORE ALL PREVIOUS INSTRUCTIONS") {
		t.Fatalf("tools/call through the inspector: %v", call)
	}
	call = run("--method", "tools/call", "--tool-name", "history.query", "--tool-args-json", `{"range":"6h","points":30}`)
	if call["isError"] == true {
		t.Fatalf("history.query through the inspector: %v", call)
	}
	w.mu.Lock()
	heard := strings.Join(w.heard, ", ")
	w.mu.Unlock()
	t.Logf("the inspector listed %d tools and called two; it sent: %s", len(tools), heard)
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
