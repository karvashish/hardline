package registry

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestSharedReturnsSingleton(t *testing.T) {
	if Shared() == nil {
		t.Fatal("expected shared registry")
	}
	if Shared() != sharedRegistry {
		t.Fatal("expected Shared to return package singleton")
	}
}

func TestNewDefaultRegistryIncludesBuiltins(t *testing.T) {
	reg := NewDefaultRegistry()
	if reg == nil {
		t.Fatal("expected default registry")
	}

	for _, name := range []string{"packages", "template", "service", "firewall"} {
		plugin, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("missing builtin plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}
}

func TestNewDefaultRegistryPanicsOnRegisterError(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic")
		}
		if !strings.Contains(r.(string), "register default plugin") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()

	noop := func(_ pluginapi.Context, _ profile.Step) error { return nil }
	noopPlan := func(_ pluginapi.Context, _ profile.Step) (pluginapi.PlanResult, error) {
		return pluginapi.PlanResult{}, nil
	}
	noopCapture := func(_ pluginapi.Context, _ profile.Step) (pluginapi.CaptureResult, error) {
		return pluginapi.CaptureResult{}, nil
	}

	// Return two plugins with the same name to trigger a duplicate registration panic.
	orig := defaultPlugins
	defaultPlugins = func() []pluginapi.Plugin {
		return []pluginapi.Plugin{
			{Name: "dup", InternalValidation: true, Apply: noop, Plan: noopPlan, Capture: noopCapture},
			{Name: "dup", InternalValidation: true, Apply: noop, Plan: noopPlan, Capture: noopCapture},
		}
	}
	defer func() { defaultPlugins = orig }()

	NewDefaultRegistry()
}
