package pluginapi

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	r := NewRegistry()

	err := r.Register(Plugin{
		Name:               "  TEMPLATE  ",
		InternalValidation: true,
		Apply:              func(Context, profile.Step) error { return nil },
		Plan: func(Context, profile.Step) (PlanResult, error) {
			return PlanResult{Summary: "ok"}, nil
		},
		Capture: func(Context, profile.Step) (CaptureResult, error) {
			return CaptureResult{}, nil
		},
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
	if !plugin.InternalValidation {
		t.Fatal("expected internal validation metadata to be preserved")
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
		Name:               "x",
		InternalValidation: true,
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

func TestEnsureValidationPolicy(t *testing.T) {
	step := profile.Step{ID: "s1", Plugin: "pkg"}

	if err := EnsureValidationPolicy(step, Plugin{Name: "pkg", InternalValidation: true}); err != nil {
		t.Fatalf("expected internally validating plugin to pass, got %v", err)
	}

	step.AllowUnvalidated = true
	if err := EnsureValidationPolicy(step, Plugin{Name: "pkg", InternalValidation: false}); err != nil {
		t.Fatalf("expected explicit allow_unvalidated to pass, got %v", err)
	}

	step.AllowUnvalidated = false
	err := EnsureValidationPolicy(step, Plugin{Name: "pkg", InternalValidation: false})
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected explicit unvalidated policy error, got %v", err)
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

func TestEnsureProfilePlugins(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(validPlugin("template")); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}
	if err := r.Register(validPlugin("service")); err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	err := EnsureProfilePlugins(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "s1", Plugin: "template"}}},
			{Steps: []profile.Step{{ID: "s2", Plugin: "service"}}},
		},
	})
	if err != nil {
		t.Fatalf("expected profile plugin validation success, got %v", err)
	}

	err = EnsureProfilePlugins(r, &profile.Profile{
		ActionFiles: []profile.ActionFile{
			{Steps: []profile.Step{{ID: "bad", Plugin: "missing"}}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "required plugin \"missing\" is not registered") {
		t.Fatalf("expected missing plugin error, got %v", err)
	}

	err = EnsureProfilePlugins(r, nil)
	if err == nil || !strings.Contains(err.Error(), "profile is nil") {
		t.Fatalf("expected nil profile error, got %v", err)
	}
}

func TestNoopCapture(t *testing.T) {
	record := NoopCapture(profile.Step{ID: "s1", Plugin: "template"}, "noop")
	if record.RollbackMode != ModeNoop {
		t.Fatalf("unexpected noop capture: %+v", record)
	}
	if len(record.Objects) != 1 || record.Objects[0].Message != "noop" {
		t.Fatalf("unexpected noop capture objects: %+v", record.Objects)
	}
}

func validPlugin(name string) Plugin {
	return Plugin{
		Name:               name,
		InternalValidation: true,
		Apply:              func(Context, profile.Step) error { return nil },
		Plan: func(Context, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		Capture: func(Context, profile.Step) (CaptureResult, error) {
			return CaptureResult{}, nil
		},
	}
}
