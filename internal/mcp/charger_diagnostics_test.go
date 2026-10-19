package mcp

import (
	"strings"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw/go/protocol"
)

func TestDiagnosticReadsPreserveAnOldChargerBindingForComparison(t *testing.T) {
	world := newWorld(t)
	box := world.connectBox()
	assistant := world.connect(box, oauth.ScopeDiagRun)
	read := func(path string) map[string]any {
		t.Helper()
		result, failed, _ := assistant.call("api_read", map[string]any{"path": path})
		if failed {
			t.Fatal("full diagnostic read failed")
		}
		transport := result["structuredContent"].(map[string]any)["data"].(map[string]any)
		return transport["response"].(map[string]any)["body"].(map[string]any)
	}
	cfg := read("/api/config")
	current := cfg["drivers"].([]any)[0].(map[string]any)["name"]
	saved := cfg["loadpoints"].([]any)[0].(map[string]any)["driver_name"]
	runtime := read("/api/drivers")["drivers"].([]any)[0].(map[string]any)["name"]
	if current != "charger-current" || saved != "charger-old" || current != runtime {
		t.Fatal("full diagnostic reads changed the names needed to identify an old binding")
	}
	_, _, asked := box.counts()
	for _, request := range asked {
		if strings.HasPrefix(request, protocol.MsgAPIReq+" ") {
			t.Fatal("troubleshooting used an owner write path")
		}
	}
}

func TestRefusedDiagnosticReadIsAnErrorWithItsBoxEvidence(t *testing.T) {
	world := newWorld(t)
	assistant := world.connect(world.connectBox(), oauth.ScopeDiagRun)
	result, failed, _ := assistant.call("api_read", map[string]any{"path": "/api/test/refused"})
	if !failed {
		t.Fatal("a refused diagnostic read looked successful")
	}
	transport := result["structuredContent"].(map[string]any)["data"].(map[string]any)
	if transport["status"] != float64(403) || transport["response"].(map[string]any)["error"] != "diagnostic read refused" {
		t.Fatal("the failed read lost its status or box evidence")
	}
}

func TestTroubleshootingGuidanceUsesFullReadsAndStatesRedactionLimits(t *testing.T) {
	for _, text := range []string{"api_catalog", "api_read", "config_get", "/api/config", "/api/drivers", "/api/loadpoints", "refused"} {
		if !strings.Contains(Instructions, text) {
			t.Errorf("missing troubleshooting guidance: %s", text)
		}
	}
	server := &Server{tools: readTools()}
	description := server.tool("config_get").description
	if !strings.Contains(description, "cannot verify") || !strings.Contains(description, "redacted") {
		t.Fatal("basic config tool does not state its diagnostic limit")
	}
	for _, tool := range []string{"api_read", "api_catalog"} {
		if strings.Contains(description, tool) {
			t.Fatal("the public basic tool recommends an unavailable tool")
		}
	}
}
