package apply

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestHandleStepDispatch(t *testing.T) {
	reg := pluginapi.NewRegistry()

	called := false
	err := reg.Register(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Validate:           func(profile.Step, map[string]json.RawMessage) error { return nil },
		Apply: func(ctx pluginapi.Context, s profile.Step) error {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected apply context profile: %+v", ctx.Profile)
			}
			if string(ctx.Overrides["ssh_port"]) != "2222" {
				t.Fatalf("unexpected overrides in apply context: %+v", ctx.Overrides)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step passed to apply: %+v", s)
			}
			return nil
		},
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
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	p.SetRuntimeOverrides(map[string]json.RawMessage{"ssh_port": json.RawMessage(`2222`)})
	if err := handleStepWithRegistry(reg, nil, p, profile.Step{ID: "u", Plugin: "unknown"}, nil); err == nil || !strings.Contains(err.Error(), "required plugin \"unknown\" is not registered") {
		t.Fatalf("expected unknown plugin failure, got %v", err)
	}

	if err := handleStepWithRegistry(reg, nil, p, profile.Step{ID: "s1", Plugin: "fake"}, nil); err != nil {
		t.Fatalf("fake plugin apply failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plugin to be called")
	}
}

func TestHandleStepWrapperAndReset(t *testing.T) {
	err := handleStepWithRegistry(registry.Shared(), nil, nil, profile.Step{
		ID:     "pkg",
		Plugin: "packages_apt",
		Config: map[string]any{"install": []any{"curl"}},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "host context is required") {
		t.Fatalf("expected shared-registry handleStep error, got %v", err)
	}
}

func TestHandleStepValidationPolicy(t *testing.T) {
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

	err = handleStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"}, nil)
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	err = handleStepWithRegistry(reg, nil, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	}, nil)
	if err != nil {
		t.Fatalf("expected allow_unvalidated to permit external plugin, got %v", err)
	}
}

func TestNewDefaultRegistries(t *testing.T) {
	reg := registry.NewDefaultRegistry()
	for _, name := range []string{"packages_apt", "packages_dnf4", "packages_dnf5", "template", "service", "firewall"} {
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

func TestRegisterPlugin(t *testing.T) {
	reg := pluginapi.NewRegistry()
	err := reg.Register(pluginapi.Plugin{
		Name:               "rb",
		InternalValidation: true,
		Validate:           func(profile.Step, map[string]json.RawMessage) error { return nil },
		Apply:              func(pluginapi.Context, profile.Step) error { return nil },
		Plan: func(pluginapi.Context, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.Context, profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{RollbackMode: pluginapi.ModeNoop}, nil
		},
		Rollback:       func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
		DetectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil },
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	plugin, ok := reg.Lookup("rb")
	if !ok {
		t.Fatal("expected plugin lookup to succeed")
	}
	if _, err := plugin.Capture(pluginapi.Context{}, profile.Step{ID: "x", Plugin: "rb"}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}
