package firewall

import (
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin(
		ApplyDeps{
			RunRoot:          func(*ssh.Client, string) error { return nil },
			NewSFTPClient:    func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile:    func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
			MarkServiceDirty: func(string) {},
		},
		RollbackDeps{},
	)

	if !plugin.InternalValidation {
		t.Fatal("expected firewall plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
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
	plugin := Plugin(
		ApplyDeps{
			RunRoot:          func(*ssh.Client, string) error { return nil },
			NewSFTPClient:    func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile:    func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
			MarkServiceDirty: func(string) {},
		},
		RollbackDeps{},
	)

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
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
	plugin := Plugin(
		ApplyDeps{
			RunRoot:          func(*ssh.Client, string) error { return nil },
			NewSFTPClient:    func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile:    func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
			MarkServiceDirty: func(string) {},
		},
		RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
		},
	)

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
		Inspector: firewallInspectorStub{include: true, statInfo: fakeFileInfo{mode: 0o644, size: 12}},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if _, err := plugin.Rollback(pluginapi.RollbackContext{}, step); err != nil {
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
