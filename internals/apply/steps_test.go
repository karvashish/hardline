package apply

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestHandleStepDispatch(t *testing.T) {
	reg := pluginapi.NewRegistry()

	called := false
	err := reg.Register(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected apply context profile: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step passed to apply: %+v", s)
			}
			return nil
		},
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	if err := handleStepWithRegistry(reg, nil, p, profile.Step{ID: "u", Plugin: "unknown"}); err != nil {
		t.Fatalf("unknown plugin should be noop, got %v", err)
	}

	if err := handleStepWithRegistry(reg, nil, p, profile.Step{ID: "s1", Plugin: "fake"}); err != nil {
		t.Fatalf("fake plugin apply failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plugin to be called")
	}
}

func TestHandleStepValidationPolicy(t *testing.T) {
	reg := pluginapi.NewRegistry()
	err := reg.Register(pluginapi.Plugin{
		Name:               "external",
		InternalValidation: false,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register external plugin failed: %v", err)
	}

	err = handleStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"})
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	err = handleStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	})
	if err != nil {
		t.Fatalf("expected allow_unvalidated to permit external plugin, got %v", err)
	}
}

func TestNewDefaultRegistries(t *testing.T) {
	reg := registry.NewDefaultRegistry()
	for _, name := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		plugin, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("missing builtin plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}

	if reg == nil {
		t.Fatal("expected shared registry")
	}
	fresh := registry.NewDefaultRegistry()
	if fresh == nil {
		t.Fatal("expected fresh default registry to be constructible")
	}
}

func TestRegisterPluginBundle(t *testing.T) {
	reg := pluginapi.NewRegistry()
	err := reg.RegisterBundle(pluginapi.PluginBundle{
		Name: "bundle",
		Plugins: []pluginapi.Plugin{{
			Name:               "rb",
			InternalValidation: true,
			Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
			Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, nil
			},
			Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
				return rollback.StepRecord{ID: "rb", Type: "rb", RollbackMode: rollback.ModeNoop}, nil
			},
		}},
	})
	if err != nil {
		t.Fatalf("register bundle failed: %v", err)
	}

	plugin, ok := reg.Lookup("rb")
	if !ok {
		t.Fatal("expected plugin lookup to succeed")
	}
	if _, err := plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{ID: "x", Plugin: "rb"}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}
