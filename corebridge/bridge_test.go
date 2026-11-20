package corebridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

// Exercise the actual iOS-generated routing config and cache across two starts.
// Replace only the system TUN and mixed listeners so this test needs no VPN entitlement.
func TestGuardStartsSealedWithExistingCache(t *testing.T) {
	directory := os.Getenv("GUARD_TEST_CONFIGS")
	for _, mode := range []string{"false", "true"} {
		raw, err := os.ReadFile(filepath.Join(directory, "tunnel-"+mode+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var config map[string]any
		if err := json.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		delete(config, "inbounds")
		raw, err = json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		selectedTag := "proxy-" + mode
		func() {
			if err := StartTunnelCore(string(raw), -1); err != "" {
				t.Fatal(err)
			}
			defer StopTunnelCore()
			group, _ := activeBox.Outbound().Outbound("guard")
			selected := func() string { return group.(adapter.OutboundGroup).Selected("tcp").Tag() }
			if selected() != "sealed" || !SelectGuardOutbound(selectedTag) || selected() != selectedTag {
				t.Fatal("unexpected selector state at startup or activation")
			}
			if !SelectGuardOutbound("sealed") || selected() != "sealed" {
				t.Fatal("guard failed to close")
			}
			if !SelectGuardOutbound(selectedTag) {
				t.Fatal("could not persist a previously open selection")
			}
		}()
		if _, err := os.Stat(filepath.Join(directory, "cache.db")); err != nil {
			t.Fatal(err)
		}
	}
}
