package packages

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlugin_ApplyPlanAndRollback(t *testing.T) {
	plugin := Plugin()

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

	if err := plugin.Apply(pluginapi.Context{Host: packagesRuntimeStub{}}, step); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, err := plugin.Plan(pluginapi.Context{
		Host: packagesRuntimeStub{},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if _, err := plugin.Capture(pluginapi.Context{Host: packagesRuntimeStub{}}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestPlugin_Validation(t *testing.T) {
	plugin := Plugin()

	err := plugin.Apply(pluginapi.Context{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"curl", "curl"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("expected duplicate package validation error, got %v", err)
	}

	_, err = plugin.Capture(pluginapi.Context{}, profile.Step{
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

	err = plugin.Apply(pluginapi.Context{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{""},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("expected empty package validation error, got %v", err)
	}

	err = plugin.Apply(pluginapi.Context{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"upgrade": "invalid-mode",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("expected invalid op mode validation error, got %v", err)
	}

	err = plugin.Apply(pluginapi.Context{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"vim;id"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid package name") {
		t.Fatalf("expected invalid package name validation error, got %v", err)
	}

	err = plugin.Apply(pluginapi.Context{}, profile.Step{
		ID:     "pkg",
		Plugin: "packages",
		Config: map[string]any{
			"install": []any{"a"},
			"purge":   []any{"a"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be both installed and purged") {
		t.Fatalf("expected install+purge conflict error, got %v", err)
	}
}
