package firewall

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApplyFirewallOverrides_AppendsTCPAndUDPRules(t *testing.T) {
	spec := &Spec{Backend: "nftables", MainConfig: MainConfigDebian, Family: "inet", Table: "filter", ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft"}
	ctx := pluginapi.Context{
		Overrides: map[string]json.RawMessage{
			OverrideKeyAllowTCPPorts: json.RawMessage(`[8080, 9090]`),
			OverrideKeyAllowUDPPorts: json.RawMessage(`[53]`),
		},
	}

	if err := applyFirewallOverrides(ctx.Overrides, spec); err != nil {
		t.Fatalf("applyFirewallOverrides: %v", err)
	}

	if len(spec.Rules) != 3 {
		t.Fatalf("expected 3 appended rules, got %d", len(spec.Rules))
	}

	byPort := make(map[int]Rule, len(spec.Rules))
	for _, r := range spec.Rules {
		if r.Chain != "input" || r.Action != "accept" {
			t.Fatalf("unexpected chain/action: %+v", r)
		}
		byPort[r.Port] = r
	}
	if byPort[8080].Proto != "tcp" || byPort[9090].Proto != "tcp" {
		t.Fatalf("expected tcp rules for 8080 and 9090, got %+v", byPort)
	}
	if byPort[53].Proto != "udp" {
		t.Fatalf("expected udp rule for 53, got %+v", byPort[53])
	}
}

func TestApplyFirewallOverrides_NoOverridesIsNoop(t *testing.T) {
	spec := &Spec{Rules: []Rule{{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"}}}
	ctx := pluginapi.Context{}

	if err := applyFirewallOverrides(ctx.Overrides, spec); err != nil {
		t.Fatalf("applyFirewallOverrides: %v", err)
	}
	if len(spec.Rules) != 1 {
		t.Fatalf("expected rules unchanged, got %d", len(spec.Rules))
	}
}

func TestApplyFirewallOverrides_NilSpecIsNoop(t *testing.T) {
	ctx := pluginapi.Context{
		Overrides: map[string]json.RawMessage{OverrideKeyAllowTCPPorts: json.RawMessage(`[80]`)},
	}
	if err := applyFirewallOverrides(ctx.Overrides, nil); err != nil {
		t.Fatalf("applyFirewallOverrides on nil spec: %v", err)
	}
}

func TestApplyFirewallOverrides_RejectsInvalidPort(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"zero", `[0]`},
		{"negative", `[-1]`},
		{"too_high", `[70000]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &Spec{}
			ctx := pluginapi.Context{
				Overrides: map[string]json.RawMessage{
					OverrideKeyAllowTCPPorts: json.RawMessage(tc.payload),
				},
			}
			err := applyFirewallOverrides(ctx.Overrides, spec)
			if err == nil || !strings.Contains(err.Error(), "invalid port") {
				t.Fatalf("expected invalid port error, got %v", err)
			}
		})
	}
}

func TestApplyFirewallOverrides_RejectsNonArrayPayload(t *testing.T) {
	spec := &Spec{}
	ctx := pluginapi.Context{
		Overrides: map[string]json.RawMessage{
			OverrideKeyAllowUDPPorts: json.RawMessage(`"53"`),
		},
	}
	err := applyFirewallOverrides(ctx.Overrides, spec)
	if err == nil || !strings.Contains(err.Error(), "must be a JSON array") {
		t.Fatalf("expected JSON array error, got %v", err)
	}
}

func TestPlugin_AppliesAllowTCPPortsOverride(t *testing.T) {
	plugin := Plugin()
	step := profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend":      "nftables",
			"main_config":  MainConfigDebian,
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
			},
		},
	}

	// The override adds a rule, so the ruleset the kernel reports back has to
	// carry it too: activation refuses a load that did not take what was asked.
	live := mustLiveRulesetJSON(&Spec{
		Backend: "nftables", MainConfig: MainConfigDebian, Family: "inet", Table: "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []Policy{
			{Chain: "input", Policy: "drop"},
			{Chain: "forward", Policy: "drop"},
			{Chain: "output", Policy: "accept"},
		},
		Rules: []Rule{
			{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
			{Chain: "input", Proto: "tcp", Port: 8080, Action: "accept"},
		},
	})

	ctx := pluginapi.Context{
		Host: firewallHelperRuntimeStub{
			runRootWithOutput: "644 12", readContent: "stale", liveRulesetJSON: live,
		},
		Overrides: map[string]json.RawMessage{
			OverrideKeyAllowTCPPorts: json.RawMessage(`[8080]`),
		},
	}

	if err := plugin.Apply(ctx, step); err != nil {
		t.Fatalf("apply with override failed: %v", err)
	}

	planCtx := pluginapi.Context{
		Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true},
		Overrides: map[string]json.RawMessage{
			OverrideKeyAllowTCPPorts: json.RawMessage(`[8080]`),
		},
	}
	if _, err := plugin.Plan(planCtx, step); err != nil {
		t.Fatalf("plan with override failed: %v", err)
	}
}
