package registry

import (
	"encoding/json"
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

	for _, name := range []string{"packages_apt", "packages_dnf4", "packages_dnf5", "template", "service", "firewall", "file_meta"} {
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
	noopRollback := func(_ pluginapi.Host, _ pluginapi.ObjectRecord) error { return nil }
	noopConflict := func(_ pluginapi.Host, _ pluginapi.ObjectRecord) []string { return nil }

	// Return two plugins with the same name to trigger a duplicate registration panic.
	orig := defaultPlugins
	defaultPlugins = func() []pluginapi.Plugin {
		return []pluginapi.Plugin{
			{Name: "dup", InternalValidation: true, Validate: func(profile.Step, map[string]json.RawMessage) error { return nil }, Apply: noop, Plan: noopPlan, Capture: noopCapture, Rollback: noopRollback, DetectConflict: noopConflict},
			{Name: "dup", InternalValidation: true, Validate: func(profile.Step, map[string]json.RawMessage) error { return nil }, Apply: noop, Plan: noopPlan, Capture: noopCapture, Rollback: noopRollback, DetectConflict: noopConflict},
		}
	}
	defer func() { defaultPlugins = orig }()

	NewDefaultRegistry()
}
