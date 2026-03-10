package builtin

import (
	"os"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestDefaultPlugins(t *testing.T) {
	runRootCalls := 0
	plugins := DefaultPlugins(
		ApplyDeps{
			RunRoot: func(*ssh.Client, string) error {
				runRootCalls++
				return nil
			},
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
		},
		RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
		},
	)

	if len(plugins) != 5 {
		t.Fatalf("expected 5 builtin plugins, got %d", len(plugins))
	}

	byName := map[string]pluginapi.Plugin{}
	for _, plugin := range plugins {
		byName[plugin.Name] = plugin
		if !plugin.InternalValidation {
			t.Fatalf("expected plugin %q to declare internal validation", plugin.Name)
		}
	}

	for _, name := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		if _, ok := byName[name]; !ok {
			t.Fatalf("missing plugin %q", name)
		}
	}

	if err := byName["packages"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "p",
		Plugin: "packages",
		Config: map[string]any{"update": true},
	}); err != nil {
		t.Fatalf("packages apply failed: %v", err)
	}

	if runRootCalls == 0 {
		t.Fatal("expected dependencies to be wired into builtin plugins")
	}
}

func TestDefaultBundle(t *testing.T) {
	bundle := DefaultBundle(ApplyDeps{}, RollbackDeps{})
	if bundle.Name != "builtin" {
		t.Fatalf("unexpected bundle name %q", bundle.Name)
	}
	if len(bundle.Plugins) != 5 {
		t.Fatalf("expected 5 plugins in bundle, got %d", len(bundle.Plugins))
	}
}
