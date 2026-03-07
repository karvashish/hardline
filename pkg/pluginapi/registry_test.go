package pluginapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApplyRegistry_RegisterAndLookup(t *testing.T) {
	r := NewApplyRegistry()

	err := r.Register(ApplyHandler{
		Type: "  TEMPLATE  ",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
		ValidateKinds: map[string]func(ApplyContext) error{
			"  SSHD  ": func(ApplyContext) error { return nil },
		},
	})
	if err != nil {
		t.Fatalf("register apply handler failed: %v", err)
	}

	h, ok := r.LookupType("template")
	if !ok {
		t.Fatalf("expected apply handler lookup success")
	}
	if h.Type != "template" {
		t.Fatalf("expected normalized handler type, got %q", h.Type)
	}

	validateFn, ok := r.LookupValidate("sshd")
	if !ok {
		t.Fatalf("expected validate lookup success")
	}
	if err := validateFn(ApplyContext{}); err != nil {
		t.Fatalf("validate fn failed: %v", err)
	}
}

func TestApplyRegistry_RegisterErrors(t *testing.T) {
	var nilReg *ApplyRegistry
	if err := nilReg.Register(ApplyHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewApplyRegistry()
	err := r.Register(ApplyHandler{Apply: func(ApplyContext, profile.Step) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("expected missing type error, got %v", err)
	}

	err = r.Register(ApplyHandler{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing Apply func") {
		t.Fatalf("expected missing apply func error, got %v", err)
	}

	err = r.Register(ApplyHandler{
		Type: "x",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("register baseline handler failed: %v", err)
	}

	err = r.Register(ApplyHandler{
		Type: "x",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}

	r2 := NewApplyRegistry()
	err = r2.Register(ApplyHandler{
		Type: "a",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
		ValidateKinds: map[string]func(ApplyContext) error{
			"": func(ApplyContext) error { return nil },
		},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("expected empty validate kind error, got %v", err)
	}

	err = r2.Register(ApplyHandler{
		Type: "b",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
		ValidateKinds: map[string]func(ApplyContext) error{
			"sshd": nil,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "nil func") {
		t.Fatalf("expected nil validate func error, got %v", err)
	}

	err = r2.Register(ApplyHandler{
		Type: "a",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
		ValidateKinds: map[string]func(ApplyContext) error{
			"sshd": func(ApplyContext) error { return nil },
		},
	})
	if err != nil {
		t.Fatalf("register handler with validation failed: %v", err)
	}

	err = r2.Register(ApplyHandler{
		Type: "b",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
		ValidateKinds: map[string]func(ApplyContext) error{
			"sshd": func(ApplyContext) error { return nil },
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate validate kind error, got %v", err)
	}
}

func TestApplyRegistry_LookupNilRegistry(t *testing.T) {
	var nilReg *ApplyRegistry
	if _, ok := nilReg.LookupType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
	if _, ok := nilReg.LookupValidate("x"); ok {
		t.Fatalf("expected nil registry validate lookup miss")
	}
}

func TestPlanRegistry_RegisterAndLookup(t *testing.T) {
	r := NewPlanRegistry()

	err := r.Register(PlanHandler{
		Type: " FIREWALL ",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{Summary: "ok", Noop: 2}, nil
		},
		ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
			"firewall": func(PlanContext) (PlanResult, error) {
				return PlanResult{Summary: "validate firewall", Noop: 2}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("register plan handler failed: %v", err)
	}

	h, ok := r.LookupType("firewall")
	if !ok {
		t.Fatalf("expected plan handler lookup success")
	}
	got, err := h.Plan(PlanContext{}, profile.Step{})
	if err != nil || got.Summary != "ok" {
		t.Fatalf("unexpected plan call result: got=%+v err=%v", got, err)
	}

	validateFn, ok := r.LookupValidate("  FIREWALL ")
	if !ok {
		t.Fatalf("expected plan validate lookup success")
	}
	validateResult, err := validateFn(PlanContext{})
	if err != nil || !strings.Contains(validateResult.Summary, "validate") {
		t.Fatalf("unexpected plan validate result: got=%+v err=%v", validateResult, err)
	}
}

func TestPlanRegistry_RegisterErrors(t *testing.T) {
	var nilReg *PlanRegistry
	if err := nilReg.Register(PlanHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewPlanRegistry()
	err := r.Register(PlanHandler{
		Type: "x",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
			"": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
		},
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be empty") {
		t.Fatalf("expected empty validate kind error, got %v", err)
	}

	err = r.Register(PlanHandler{
		Type: "y",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
			"k": nil,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "nil func") {
		t.Fatalf("expected nil validate func error, got %v", err)
	}

	err = r.Register(PlanHandler{
		Type: "x",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, errors.New("boom")
		},
	})
	if err != nil {
		t.Fatalf("register plan handler failed: %v", err)
	}

	err = r.Register(PlanHandler{
		Type: "x",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}

	err = r.Register(PlanHandler{
		Type: "y",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
			"k": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
		},
	})
	if err != nil {
		t.Fatalf("register secondary handler failed: %v", err)
	}

	err = r.Register(PlanHandler{
		Type: "z",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
		ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
			"k": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate validate kind error, got %v", err)
	}
}

func TestPlanRegistry_LookupNilRegistry(t *testing.T) {
	var nilReg *PlanRegistry
	if _, ok := nilReg.LookupType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
	if _, ok := nilReg.LookupValidate("x"); ok {
		t.Fatalf("expected nil registry validate lookup miss")
	}
}

func TestRollbackRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRollbackRegistry()

	err := r.Register(RollbackHandler{
		Type: "  TEMPLATE  ",
		Capture: func(RollbackContext, profile.Step) (step rollback.StepRecord, err error) {
			return rollback.StepRecord{Type: "template"}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}

	h, ok := r.LookupType("template")
	if !ok {
		t.Fatalf("expected rollback handler lookup success")
	}
	if h.Type != "template" {
		t.Fatalf("expected normalized handler type, got %q", h.Type)
	}
}

func TestRollbackRegistry_RegisterErrors(t *testing.T) {
	var nilReg *RollbackRegistry
	if err := nilReg.Register(RollbackHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewRollbackRegistry()
	err := r.Register(RollbackHandler{})
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("expected missing type error, got %v", err)
	}

	err = r.Register(RollbackHandler{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing Capture func") {
		t.Fatalf("expected missing capture func error, got %v", err)
	}

	err = r.Register(RollbackHandler{
		Type: "x",
		Capture: func(RollbackContext, profile.Step) (rollback.StepRecord, error) {
			return rollback.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}

	err = r.Register(RollbackHandler{
		Type: "x",
		Capture: func(RollbackContext, profile.Step) (rollback.StepRecord, error) {
			return rollback.StepRecord{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}
}

func TestRollbackRegistry_LookupNilRegistry(t *testing.T) {
	var nilReg *RollbackRegistry
	if _, ok := nilReg.LookupType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
}
