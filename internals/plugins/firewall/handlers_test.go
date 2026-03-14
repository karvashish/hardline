package firewall

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin()

	if !plugin.InternalValidation {
		t.Fatal("expected firewall plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.ApplyContext{Host: firewallHelperRuntimeStub{runRootWithOutput: "644 12", readContent: "stale"}}, profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend": "ufw",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Fatalf("expected firewall validation error, got %v", err)
	}

	_, err = plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend": "ufw",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Fatalf("expected rollback firewall validation error, got %v", err)
	}
}

func TestPlugin_ApplyUsesValidationFlow(t *testing.T) {
	plugin := Plugin()

	err := plugin.Apply(pluginapi.ApplyContext{Host: firewallHelperRuntimeStub{runRootWithOutput: "644 12", readContent: "stale"}}, profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend":      "nftables",
			"family":       "inet",
			"table":        "filter",
			"managed_dest": "/etc/nftables.d/99-hardline-firewall.nft",
			"policies": []any{
				map[string]any{"chain": "input", "policy": "drop"},
				map[string]any{"chain": "forward", "policy": "drop"},
				map[string]any{"chain": "output", "policy": "accept"},
			},
			"rules": []any{
				map[string]any{"chain": "input", "proto": "tcp", "port": 22, "action": "accept"},
				map[string]any{"chain": "input", "ct_states": []any{"established", "related"}, "action": "accept"},
			},
		},
	})
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
}

func TestPlugin_PlanAndRollback(t *testing.T) {
	plugin := Plugin()

	step := profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend":      "nftables",
			"family":       "inet",
			"table":        "filter",
			"managed_dest": "/etc/nftables.d/99-hardline-firewall.nft",
			"policies": []any{
				map[string]any{"chain": "input", "policy": "drop"},
				map[string]any{"chain": "forward", "policy": "drop"},
				map[string]any{"chain": "output", "policy": "accept"},
			},
			"rules": []any{
				map[string]any{"chain": "input", "proto": "tcp", "port": 22, "action": "accept"},
				map[string]any{"chain": "input", "ct_states": []any{"established", "related"}, "action": "accept"},
			},
		},
	}

	if _, err := plugin.Plan(pluginapi.PlanContext{
		Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if _, err := plugin.Rollback(pluginapi.RollbackContext{Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true}}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestValidateFirewallSpec(t *testing.T) {
	if err := validateFirewallSpec(nil); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected nil config error, got %v", err)
	}
	if err := validateFirewallSpec(&Spec{}); err == nil || !strings.Contains(err.Error(), "backend is required") {
		t.Fatalf("expected backend error, got %v", err)
	}
	spec := validDeterministicFirewallSpec()
	spec.ManagedDest = ""
	if err := validateFirewallSpec(spec); err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
		t.Fatalf("expected managed_dest error, got %v", err)
	}
}
