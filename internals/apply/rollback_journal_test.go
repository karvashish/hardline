package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestCaptureStepRecord_ValidateNoop(t *testing.T) {
	record, err := captureStepRecord(nil, nil, profile.Step{ID: "v", Type: "validate"})
	if err != nil {
		t.Fatalf("captureStepRecord failed: %v", err)
	}
	if record.RollbackMode != rollback.ModeNoop {
		t.Fatalf("expected noop rollback mode, got %q", record.RollbackMode)
	}
	if len(record.Objects) != 1 || record.Objects[0].Kind != rollback.ObjectValidate {
		t.Fatalf("unexpected validate rollback object: %+v", record.Objects)
	}
}

func TestCaptureStepRecord_UnknownNoop(t *testing.T) {
	record, err := captureStepRecord(nil, nil, profile.Step{ID: "u", Type: "mystery"})
	if err != nil {
		t.Fatalf("captureStepRecord failed: %v", err)
	}
	if record.RollbackMode != rollback.ModeNoop {
		t.Fatalf("expected noop rollback mode, got %q", record.RollbackMode)
	}
	if len(record.Objects) != 1 || !strings.Contains(record.Objects[0].Message, "unknown step type") {
		t.Fatalf("unexpected unknown-step rollback object: %+v", record.Objects)
	}
}

func TestCaptureStepRecord_DelegatesToRegistry(t *testing.T) {
	prev := applyRollbackRegistry
	defer func() {
		applyRollbackRegistry = prev
	}()

	registry := pluginapi.NewRollbackRegistry()
	called := false
	err := registry.Register(pluginapi.RollbackHandler{
		Type: "fake",
		Capture: func(pluginapi.RollbackContext, profile.Step) (rollback.StepRecord, error) {
			called = true
			return rollback.StepRecord{
				ID:           "f1",
				Type:         "fake",
				RollbackMode: rollback.ModeDeterministic,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}
	applyRollbackRegistry = registry

	record, err := captureStepRecord(nil, nil, profile.Step{ID: "f1", Type: "fake"})
	if err != nil {
		t.Fatalf("captureStepRecord failed: %v", err)
	}
	if !called {
		t.Fatal("expected rollback handler to be invoked")
	}
	if record.Type != "fake" || record.ID != "f1" {
		t.Fatalf("unexpected captured record: %+v", record)
	}
}

func TestCaptureStepRecord_HandlerErrorBubbles(t *testing.T) {
	prev := applyRollbackRegistry
	defer func() {
		applyRollbackRegistry = prev
	}()

	registry := pluginapi.NewRollbackRegistry()
	err := registry.Register(pluginapi.RollbackHandler{
		Type: "fake",
		Capture: func(pluginapi.RollbackContext, profile.Step) (rollback.StepRecord, error) {
			return rollback.StepRecord{}, errors.New("capture boom")
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}
	applyRollbackRegistry = registry

	_, gotErr := captureStepRecord(nil, nil, profile.Step{ID: "f1", Type: "fake"})
	if gotErr == nil || !strings.Contains(gotErr.Error(), "capture boom") {
		t.Fatalf("expected capture error, got %v", gotErr)
	}
}
