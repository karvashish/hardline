package firewall

import (
	"errors"
	"os"
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

	err := plugin.Apply(pluginapi.Context{Host: firewallHelperRuntimeStub{runRootWithOutput: "644 12", readContent: "stale"}}, profile.Step{
		ID:     "fw",
		Plugin: "firewall",
		Config: map[string]any{
			"backend": "ufw",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Fatalf("expected firewall validation error, got %v", err)
	}

	_, err = plugin.Capture(pluginapi.Context{}, profile.Step{
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
			{Chain: "input", CTStates: []string{"established", "related"}, Action: "accept"},
		},
	})

	err := plugin.Apply(pluginapi.Context{Host: firewallHelperRuntimeStub{
		runRootWithOutput: "644 12", readContent: "stale", liveRulesetJSON: live,
	}}, profile.Step{
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
				map[string]any{"chain": "input", "ct_states": []any{"established", "related"}, "action": "accept"},
			},
		},
	}

	if _, err := plugin.Plan(pluginapi.Context{
		Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if _, err := plugin.Capture(pluginapi.Context{Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true}}, step); err != nil {
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

	spec = validDeterministicFirewallSpec()
	spec.MainConfig = ""
	if err := validateFirewallSpec(spec); err == nil || !strings.Contains(err.Error(), "main_config is required") {
		t.Fatalf("expected main_config error, got %v", err)
	}

	for _, bad := range []string{"/etc/nftables.d/99-hardline.nft", "/tmp/nftables.conf", "/etc/passwd"} {
		spec = validDeterministicFirewallSpec()
		spec.MainConfig = bad
		if err := validateFirewallSpec(spec); err == nil || !strings.Contains(err.Error(), "unsupported firewall main_config") {
			t.Fatalf("main_config %q: expected rejection, got %v", bad, err)
		}
	}

	for _, good := range []string{MainConfigDebian, MainConfigRHEL} {
		spec = validDeterministicFirewallSpec()
		spec.MainConfig = good
		if err := validateFirewallSpec(spec); err != nil {
			t.Fatalf("main_config %q: expected acceptance, got %v", good, err)
		}
	}
}

func TestRHELMainConfigWiring(t *testing.T) {
	var cmds []string
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			if strings.HasPrefix(cmd, "grep -E -q") || strings.HasPrefix(cmd, "test -e ") {
				return errors.New("missing")
			}
			return nil
		},
		writeRootFile: func(string, []byte, os.FileMode) error { return nil },
	}

	spec := validDeterministicFirewallSpec()
	spec.MainConfig = MainConfigRHEL
	if err := Apply(pluginapi.Context{Host: host}, spec); err == nil {
		t.Fatal("expected the second include check to fail on this stub")
	}

	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "'/etc/sysconfig/nftables.conf'") {
		t.Fatalf("expected the RHEL main config to be used, got %v", cmds)
	}
	if strings.Contains(joined, "/etc/nftables.conf'") {
		t.Fatalf("Debian main config must not appear in a RHEL run, got %v", cmds)
	}
}

func TestIncludeLineNamesTheManagedFile(t *testing.T) {
	if got := IncludeLine("/etc/nftables.d/99-hardline-firewall.nft"); got != `include "/etc/nftables.d/99-hardline-firewall.nft"` {
		t.Fatalf("unexpected include line: %q", got)
	}
	if got := IncludeLine("/etc/hardline.d/99-other-firewall.nft"); got != `include "/etc/hardline.d/99-other-firewall.nft"` {
		t.Fatalf("include line must name managed_dest, got %q", got)
	}
}

func TestFirewallConfigTestUsesTheProfileMainConfig(t *testing.T) {
	for _, mainConfig := range []string{MainConfigDebian, MainConfigRHEL} {
		var got string
		host := firewallExecHostStub{runRoot: func(cmd string) error {
			got = cmd
			return nil
		}}
		if err := firewallConfigTest(host, mainConfig); err != nil {
			t.Fatalf("main_config %q: unexpected error: %v", mainConfig, err)
		}
		want := "nft -c -f '" + mainConfig + "' >/dev/null 2>&1"
		if got != want {
			t.Fatalf("main_config %q: ran %q, want %q", mainConfig, got, want)
		}
	}

	if err := firewallConfigTest(nil, MainConfigDebian); err == nil {
		t.Fatal("expected a host-required error")
	}
	if err := firewallConfigTest(firewallExecHostStub{}, "/etc/evil.conf"); err == nil {
		t.Fatal("expected an unsupported main_config to be rejected")
	}
}

func TestPlanValidateChecksTheProfileMainConfig(t *testing.T) {
	var cmds []string
	host := firewallExecHostStub{runRoot: func(cmd string) error {
		cmds = append(cmds, cmd)
		return nil
	}}
	if _, err := ValidatePlan(host, MainConfigRHEL, "/etc/nftables.d/99-hardline-firewall.nft"); err != nil {
		t.Fatalf("ValidatePlan failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "nft -c -f '/etc/sysconfig/nftables.conf'") {
		t.Fatalf("plan validated the wrong file: %v", cmds)
	}
	if strings.Contains(joined, "nft -c -f '/etc/nftables.conf'") {
		t.Fatalf("plan validated the Debian path on a RHEL profile: %v", cmds)
	}
}
