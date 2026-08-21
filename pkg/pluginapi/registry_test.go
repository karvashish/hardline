package pluginapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	err := r.Register(Plugin{
		Name:     "  TEMPLATE  ",
		Validate: func(profile.Step, map[string]json.RawMessage) error { return nil },
		Apply:    func(Context, profile.Step) error { return nil },
		Plan: func(Context, profile.Step) (PlanResult, error) {
			return PlanResult{Summary: "ok"}, nil
		},
		Capture: func(Context, profile.Step) (CaptureResult, error) {
			return CaptureResult{}, nil
		},
		Rollback:       func(Host, ObjectRecord) error { return nil },
		DetectConflict: func(Host, ObjectRecord) []string { return nil },
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	plugin, ok := r.Lookup("template")
	if !ok {
		t.Fatal("expected plugin lookup success")
	}
	if plugin.Name != "template" {
		t.Fatalf("expected normalized plugin name, got %q", plugin.Name)
	}
}

func TestRegistryRegisterErrors(t *testing.T) {
	var nilReg *Registry
	if err := nilReg.Register(Plugin{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewRegistry()
	err := r.Register(Plugin{})
	if err == nil || !strings.Contains(err.Error(), "name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}

	err = r.Register(Plugin{
		Name:     "x",
		Validate: func(profile.Step, map[string]json.RawMessage) error { return nil },
		Plan: func(Context, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		Capture: func(Context, profile.Step) (CaptureResult, error) {
			return CaptureResult{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "missing Apply func") {
		t.Fatalf("expected missing apply error, got %v", err)
	}

	err = r.Register(Plugin{
		Name:    "x",
		Apply:   func(Context, profile.Step) error { return nil },
		Plan:    func(Context, profile.Step) (PlanResult, error) { return PlanResult{}, nil },
		Capture: func(Context, profile.Step) (CaptureResult, error) { return CaptureResult{}, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "missing Rollback func") {
		t.Fatalf("expected missing rollback error, got %v", err)
	}

	err = r.Register(Plugin{
		Name:     "x",
		Apply:    func(Context, profile.Step) error { return nil },
		Plan:     func(Context, profile.Step) (PlanResult, error) { return PlanResult{}, nil },
		Capture:  func(Context, profile.Step) (CaptureResult, error) { return CaptureResult{}, nil },
		Rollback: func(Host, ObjectRecord) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "missing DetectConflict func") {
		t.Fatalf("expected missing detect-conflict error, got %v", err)
	}

	err = r.Register(Plugin{
		Name:           "x",
		Apply:          func(Context, profile.Step) error { return nil },
		Plan:           func(Context, profile.Step) (PlanResult, error) { return PlanResult{}, nil },
		Capture:        func(Context, profile.Step) (CaptureResult, error) { return CaptureResult{}, nil },
		Rollback:       func(Host, ObjectRecord) error { return nil },
		DetectConflict: func(Host, ObjectRecord) []string { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "missing Validate func") {
		t.Fatalf("expected missing validate error, got %v", err)
	}

	err = r.Register(validPlugin("x"))
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	err = r.Register(validPlugin("x"))
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate plugin error, got %v", err)
	}
}

func TestRegistryLookupNilRegistry(t *testing.T) {
	var nilReg *Registry
	if _, ok := nilReg.Lookup("x"); ok {
		t.Fatal("expected nil registry lookup miss")
	}
}

func TestRegistryRegisterMultiplePlugins(t *testing.T) {
	r := NewRegistry()
	for _, name := range []string{"x", "y"} {
		if err := r.Register(validPlugin(name)); err != nil {
			t.Fatalf("register plugin %q failed: %v", name, err)
		}
	}
	if _, ok := r.Lookup("x"); !ok {
		t.Fatal("expected plugin x in registry")
	}
	if _, ok := r.Lookup("y"); !ok {
		t.Fatal("expected plugin y in registry")
	}
}

func TestRequireStepPlugin(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(validPlugin("template")); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	plugin, err := RequireStepPlugin(r, profile.Step{ID: "s1", Plugin: " TEMPLATE "})
	if err != nil {
		t.Fatalf("expected plugin lookup success, got %v", err)
	}
	if plugin.Name != "template" {
		t.Fatalf("expected normalized plugin name, got %q", plugin.Name)
	}

	_, err = RequireStepPlugin(r, profile.Step{ID: "s2"})
	if err == nil || !strings.Contains(err.Error(), "plugin is required") {
		t.Fatalf("expected missing plugin error, got %v", err)
	}

	_, err = RequireStepPlugin(r, profile.Step{ID: "s3", Plugin: "missing"})
	if err == nil || !strings.Contains(err.Error(), "required plugin \"missing\" is not registered") {
		t.Fatalf("expected missing registration error, got %v", err)
	}
}

func TestValidateProfileSteps(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(validPlugin("template")); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}
	if err := r.Register(validPlugin("service")); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	err := ValidateProfileSteps(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "s1", Plugin: "template"}}},
			{Steps: []profile.Step{{ID: "s2", Plugin: "service"}}},
		},
	}, nil)
	if err != nil {
		t.Fatalf("expected profile plugin validation success, got %v", err)
	}

	err = ValidateProfileSteps(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "bad", Plugin: "missing"}}},
		},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "required plugin \"missing\" is not registered") {
		t.Fatalf("expected missing plugin error, got %v", err)
	}

	err = ValidateProfileSteps(r, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "profile is nil") {
		t.Fatalf("expected nil profile error, got %v", err)
	}
}

func TestValidateProfileSteps_RunsPluginValidator(t *testing.T) {
	r := NewRegistry()
	plugin := validPlugin("template")
	var seen map[string]json.RawMessage
	plugin.Validate = func(step profile.Step, overrides map[string]json.RawMessage) error {
		seen = overrides
		return fmt.Errorf("dest %q is not a drop-in", step.ID)
	}
	if err := r.Register(plugin); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	overrides := map[string]json.RawMessage{"allow_tcp_ports": json.RawMessage("[22]")}
	err := ValidateProfileSteps(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "s1", Plugin: "template"}}},
		},
	}, overrides)
	if err == nil || !strings.Contains(err.Error(), `step "s1" (template): dest "s1" is not a drop-in`) {
		t.Fatalf("expected the plugin validator error, got %v", err)
	}
	if string(seen["allow_tcp_ports"]) != "[22]" {
		t.Fatalf("expected the resolved overrides to reach the validator, got %v", seen)
	}
}

func TestValidateProfileStepsHandsTheValidatorItsOwnOverrides(t *testing.T) {
	r := NewRegistry()
	plugin := validPlugin("template")
	plugin.Validate = func(_ profile.Step, overrides map[string]json.RawMessage) error {
		overrides["allow_tcp_ports"][1] = '9'
		overrides["injected"] = json.RawMessage("true")
		return nil
	}
	if err := r.Register(plugin); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	overrides := map[string]json.RawMessage{"allow_tcp_ports": json.RawMessage("[22]")}
	err := ValidateProfileSteps(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "s1", Plugin: "template"}}},
		},
	}, overrides)
	if err != nil {
		t.Fatalf("ValidateProfileSteps failed: %v", err)
	}
	if string(overrides["allow_tcp_ports"]) != "[22]" || len(overrides) != 1 {
		t.Fatalf("a validator rewrote what plan and apply will read: %v", overrides)
	}
}

func validPlugin(name string) Plugin {
	return Plugin{
		Name:     name,
		Validate: func(profile.Step, map[string]json.RawMessage) error { return nil },
		Apply:    func(Context, profile.Step) error { return nil },
		Plan: func(Context, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		Capture: func(Context, profile.Step) (CaptureResult, error) {
			return CaptureResult{}, nil
		},
		Rollback:       func(Host, ObjectRecord) error { return nil },
		DetectConflict: func(Host, ObjectRecord) []string { return nil },
	}
}
