package plan

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegisterPluginAndPlanStep(t *testing.T) {
	reg := pluginapi.NewRegistry()

	called := false
	err := reg.Register(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected profile in plan context: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step in plan handler: %+v", s)
			}
			return pluginapi.PlanResult{Summary: "fake summary", Details: []string{"detail"}, Diff: []string{"diff"}, Noop: 1}, nil
		},
		Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	sp, err := planStepWithRegistry(reg, nil, p, profile.Step{ID: "s1", Plugin: "fake", Severity: "high", RiskClass: "r"})
	if err != nil {
		t.Fatalf("planStep fake failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plan handler to be called")
	}
	if sp.Summary != "fake summary" || sp.Severity != "high" || len(sp.Details) != 1 || len(sp.Diff) != 1 || sp.Noop != 1 {
		t.Fatalf("unexpected step plan from fake: %+v", sp)
	}
}

func TestPlanStepUnknownPlugin(t *testing.T) {
	_, err := planStep(nil, &profile.Profile{}, profile.Step{ID: "u", Plugin: "unknown"})
	if err == nil || !strings.Contains(err.Error(), "required plugin \"unknown\" is not registered") {
		t.Fatalf("expected unknown plugin failure, got %v", err)
	}
}

func TestPlanStepValidationPolicy(t *testing.T) {
	reg := pluginapi.NewRegistry()
	err := reg.Register(pluginapi.Plugin{
		Name:               "external",
		InternalValidation: false,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register external plugin failed: %v", err)
	}

	_, err = planStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"})
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	sp, err := planStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	})
	if err != nil {
		t.Fatalf("expected allow_unvalidated plan success, got %v", err)
	}
	if len(sp.Details) == 0 || !strings.Contains(sp.Details[len(sp.Details)-1], "allow_unvalidated=true") {
		t.Fatalf("expected explicit unvalidated detail, got %+v", sp)
	}
}

func TestPlanUsesSharedRegistry(t *testing.T) {
	r := registry.Shared()
	for _, name := range []string{"packages", "template", "service", "firewall"} {
		plugin, ok := r.Lookup(name)
		if !ok {
			t.Fatalf("missing shared plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}
}
