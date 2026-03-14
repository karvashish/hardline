package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestCaptureStepRecord_UnknownPluginFails(t *testing.T) {
	_, err := captureStepRecord(nil, nil, profile.Step{ID: "u", Plugin: "mystery"})
	if err == nil || !strings.Contains(err.Error(), "required plugin \"mystery\" is not registered") {
		t.Fatalf("expected missing plugin error, got %v", err)
	}
}

func TestCaptureStepRecord_DelegatesToRegistry(t *testing.T) {
	registry := pluginapi.NewRegistry()
	called := false
	err := registry.Register(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.CaptureResult, error) {
			called = true
			return pluginapi.CaptureResult{
				RollbackMode: rollback.ModeDeterministic,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}
	record, err := captureStepRecordWithRegistry(registry, nil, nil, profile.Step{ID: "f1", Plugin: "fake"})
	if err != nil {
		t.Fatalf("captureStepRecord failed: %v", err)
	}
	if !called {
		t.Fatal("expected rollback handler to be invoked")
	}
	if record.RollbackMode != rollback.ModeDeterministic {
		t.Fatalf("unexpected captured record: %+v", record)
	}
}

func TestCaptureStepRecord_HandlerErrorBubbles(t *testing.T) {
	registry := pluginapi.NewRegistry()
	err := registry.Register(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, errors.New("capture boom")
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}
	_, gotErr := captureStepRecordWithRegistry(registry, nil, nil, profile.Step{ID: "f1", Plugin: "fake"})
	if gotErr == nil || !strings.Contains(gotErr.Error(), "capture boom") {
		t.Fatalf("expected capture error, got %v", gotErr)
	}
}

func TestCaptureStepRecord_ValidationPolicy(t *testing.T) {
	registry := pluginapi.NewRegistry()
	err := registry.Register(pluginapi.Plugin{
		Name:               "external",
		InternalValidation: false,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	_, gotErr := captureStepRecordWithRegistry(registry, nil, nil, profile.Step{ID: "x", Plugin: "external"})
	if gotErr == nil || !strings.Contains(gotErr.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", gotErr)
	}
}
