package plan

import (
	"encoding/json"
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
		Validate:           func(profile.Step, map[string]json.RawMessage) error { return nil },
		Apply:              func(pluginapi.Context, profile.Step) error { return nil },
		Plan: func(ctx pluginapi.Context, s profile.Step) (pluginapi.PlanResult, error) {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected profile in plan context: %+v", ctx.Profile)
			}
			if string(ctx.Overrides["ssh_port"]) != "2222" {
				t.Fatalf("unexpected overrides in plan context: %+v", ctx.Overrides)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step in plan handler: %+v", s)
			}
			return pluginapi.PlanResult{Summary: "fake summary", Details: []string{"detail"}, Diff: []string{"diff"}, WillChange: true}, nil
		},
		Capture: func(pluginapi.Context, profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		},
		Rollback:       func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
		DetectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil },
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	p.SetRuntimeOverrides(map[string]json.RawMessage{"ssh_port": json.RawMessage(`2222`)})
	sp, err := planStepWithRegistry(reg, nil, p, profile.Step{ID: "s1", Plugin: "fake"}, nil)
	if err != nil {
		t.Fatalf("planStep fake failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plan handler to be called")
	}
	if sp.Summary != "fake summary" || len(sp.Details) != 1 || len(sp.Diff) != 1 || !sp.WillChange {
		t.Fatalf("unexpected step plan from fake: %+v", sp)
	}
}

func TestPlanStepUnknownPlugin(t *testing.T) {
	_, err := planStepWithRegistry(registry.Shared(), nil, &profile.Profile{}, profile.Step{ID: "u", Plugin: "unknown"}, nil)
	if err == nil || !strings.Contains(err.Error(), "required plugin \"unknown\" is not registered") {
		t.Fatalf("expected unknown plugin failure, got %v", err)
	}
}

func TestPlanStepValidationPolicy(t *testing.T) {
	reg := pluginapi.NewRegistry()
	err := reg.Register(pluginapi.Plugin{
		Name:               "external",
		InternalValidation: false,
		Apply:              func(pluginapi.Context, profile.Step) error { return nil },
		Plan: func(pluginapi.Context, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.Context, profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		},
		Rollback:       func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
		DetectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil },
	})
	if err != nil {
		t.Fatalf("register external plugin failed: %v", err)
	}

	_, err = planStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"}, nil)
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	sp, err := planStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	}, nil)
	if err != nil {
		t.Fatalf("expected allow_unvalidated plan success, got %v", err)
	}
	if len(sp.Details) == 0 || !strings.Contains(sp.Details[len(sp.Details)-1], "allow_unvalidated=true") {
		t.Fatalf("expected explicit unvalidated detail, got %+v", sp)
	}
}

func TestPlanUsesSharedRegistry(t *testing.T) {
	r := registry.Shared()
	for _, name := range []string{"packages_apt", "packages_dnf4", "packages_dnf5", "template", "service", "firewall"} {
		plugin, ok := r.Lookup(name)
		if !ok {
			t.Fatalf("missing shared plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}
}
