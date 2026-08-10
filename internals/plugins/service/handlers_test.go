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

// TestValidateRestartPolicy closes the enum. Before this, anything that was not
// "always" behaved roughly like "on_change", so a typo silently bought the
// weaker behaviour: a profile asking to restart unconditionally would skip it.
func TestValidateRestartPolicy(t *testing.T) {
	spec := func(state string, p *RestartPolicy) *Spec {
		return &Spec{Name: "ssh.service", State: state, RestartPolicy: p}
	}

	rejects := map[string]*Spec{
		"unknown type":         spec("restarted", &RestartPolicy{Type: "on-change"}),
		"empty type":           spec("restarted", &RestartPolicy{Type: ""}),
		"always with steps":    spec("restarted", &RestartPolicy{Type: "always", Steps: []string{"a"}}),
		"on_change no steps":   spec("restarted", &RestartPolicy{Type: "on_change"}),
		"empty step id":        spec("restarted", &RestartPolicy{Type: "on_change", Steps: []string{" "}}),
		"duplicate step id":    spec("restarted", &RestartPolicy{Type: "on_change", Steps: []string{"a", "a"}}),
		"policy without state": spec("", &RestartPolicy{Type: "always"}),
	}
	for name, s := range rejects {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceSpec(s); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	accepts := map[string]*Spec{
		"always":    spec("restarted", &RestartPolicy{Type: "always"}),
		"on_change": spec("reloaded", &RestartPolicy{Type: "on_change", Steps: []string{"drop-in"}}),
		"absent":    spec("started", nil),
	}
	for name, s := range accepts {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceSpec(s); err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}
