package service

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin()

	if !plugin.InternalValidation {
		t.Fatal("expected service plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.Context{}, profile.Step{
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

	_, err = plugin.Capture(pluginapi.Context{}, profile.Step{
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
	if err := validateServiceSpec(&Spec{}); err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected missing name validation error, got %v", err)
	}
	if err := validateServiceSpec(&Spec{Name: "ssh", State: "reload-or-restart"}); err != nil {
		t.Fatalf("expected reload-or-restart validation success, got %v", err)
	}
}

func TestPlugin_ApplyPlanAndRollback(t *testing.T) {
	plugin := Plugin()

	step := profile.Step{
		ID:     "svc",
		Plugin: "service",
		Config: map[string]any{
			"name":  "ssh",
			"state": "started",
		},
	}

	if err := plugin.Apply(pluginapi.Context{Host: serviceRuntimeStub{}}, step); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if _, err := plugin.Plan(pluginapi.Context{
		Host: serviceRuntimeStub{},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if _, err := plugin.Capture(pluginapi.Context{Host: serviceRuntimeStub{}}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestPlugin_DecodeErrors(t *testing.T) {
	plugin := Plugin()
	step := profile.Step{
		ID:     "svc",
		Plugin: "service",
		Config: map[string]any{
			"name": 123,
		},
	}

	if err := plugin.Apply(pluginapi.Context{}, step); err == nil {
		t.Fatal("expected apply decode error")
	}
	if _, err := plugin.Plan(pluginapi.Context{Host: serviceRuntimeStub{}}, step); err == nil {
		t.Fatal("expected plan decode error")
	}
	if _, err := plugin.Capture(pluginapi.Context{}, step); err == nil {
		t.Fatal("expected rollback decode error")
	}
}
