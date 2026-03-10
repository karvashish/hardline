package service

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin(
		ApplyDeps{RunRoot: func(*ssh.Client, string) error { return nil }},
		RollbackDeps{RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil }},
	)

	if !plugin.InternalValidation {
		t.Fatal("expected service plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "svc",
		Plugin: "service",
		Config: map[string]any{
			"name":  "ssh",
			"state": "explode",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported service state") {
		t.Fatalf("expected service validation error, got %v", err)
	}

	_, err = plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{
		ID:     "svc",
		Plugin: "service",
		Config: map[string]any{
			"name":  "ssh",
			"state": "explode",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported service state") {
		t.Fatalf("expected rollback service validation error, got %v", err)
	}

	if err := validateServiceSpec(nil); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected nil config validation error, got %v", err)
	}
}

func TestPlugin_ApplyPlanAndRollback(t *testing.T) {
	plugin := Plugin(
		ApplyDeps{RunRoot: func(*ssh.Client, string) error { return nil }},
		RollbackDeps{RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil }},
	)

	step := profile.Step{
		ID:     "svc",
		Plugin: "service",
		Config: map[string]any{
			"name":  "ssh",
			"state": "started",
		},
	}

	if err := plugin.Apply(pluginapi.ApplyContext{}, step); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, err := plugin.Plan(pluginapi.PlanContext{
		Runtime: serviceRuntimeStub{},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if _, err := plugin.Rollback(pluginapi.RollbackContext{}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}
