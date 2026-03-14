package main

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin()

	if !plugin.InternalValidation {
		t.Fatal("expected firewall_template plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "ft",
		Plugin: "firewall_template",
		Config: map[string]any{
			"backend": "nftables",
			"policy":  "allow",
			"allow": []any{
				map[string]any{"port": 0, "proto": "tcp"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected firewall_template validation error, got %v", err)
	}

	_, err = plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{
		ID:     "ft",
		Plugin: "firewall_template",
		Config: map[string]any{
			"backend": "nftables",
			"policy":  "allow",
			"allow": []any{
				map[string]any{"port": 0, "proto": "tcp"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected rollback firewall_template validation error, got %v", err)
	}
}

func TestPlugin_ApplyUsesValidationFlow(t *testing.T) {
	plugin := Plugin()

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "ft",
		Plugin: "firewall_template",
		Config: map[string]any{
			"backend": "nftables",
			"policy":  "allow",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "profile context is required") {
		t.Fatalf("expected firewall_template apply to reach execution path, got %v", err)
	}
}

func TestPlugin_PlanAndRollback(t *testing.T) {
	plugin := Plugin()

	step := profile.Step{
		ID:     "ft",
		Plugin: "firewall_template",
		Config: map[string]any{
			"backend": "nftables",
			"policy":  "allow",
		},
	}

	if _, err := plugin.Plan(pluginapi.PlanContext{
		Host: fwTemplateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 10}},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if _, err := plugin.Rollback(pluginapi.RollbackContext{Host: fwTemplateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 10}}}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestValidateFirewallTemplateSpec(t *testing.T) {
	if err := validateFirewallTemplateSpec(nil); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected nil config error, got %v", err)
	}
	if err := validateFirewallTemplateSpec(&Spec{}); err == nil || !strings.Contains(err.Error(), "backend is required") {
		t.Fatalf("expected backend error, got %v", err)
	}
	if err := validateFirewallTemplateSpec(&Spec{Backend: "nftables"}); err == nil || !strings.Contains(err.Error(), "policy is required") {
		t.Fatalf("expected policy error, got %v", err)
	}
	err := validateFirewallTemplateSpec(&Spec{
		Backend: "nftables",
		Policy:  "allow",
		Allow:   []AllowRule{{Port: 22, Proto: "sctp"}},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall_template protocol") {
		t.Fatalf("expected proto validation error, got %v", err)
	}
}
