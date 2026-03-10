package packages

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestPlugin_ApplyPlanAndRollback(t *testing.T) {
	plugin := Plugin(
		ApplyDeps{RunRoot: func(*ssh.Client, string) error { return nil }},
		RollbackDeps{RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil }},
	)

	if !plugin.InternalValidation {
		t.Fatal("expected packages plugin to declare internal validation")
	}

	step := profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"curl"},
		},
	}

	if err := plugin.Apply(pluginapi.ApplyContext{}, step); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, err := plugin.Plan(pluginapi.PlanContext{
		Runtime: packagesRuntimeStub{},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if _, err := plugin.Rollback(pluginapi.RollbackContext{}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestPlugin_Validation(t *testing.T) {
	plugin := Plugin(ApplyDeps{}, RollbackDeps{})

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"curl", "curl"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate package validation error, got %v", err)
	}

	_, err = plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"curl", "curl"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected rollback duplicate package validation error, got %v", err)
	}

	if err := validatePackageSpec(nil); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected nil config validation error, got %v", err)
	}

	err = plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{""},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("expected empty package validation error, got %v", err)
	}
}
