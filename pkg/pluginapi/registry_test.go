package pluginapi

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegistry_RegisterApplyAndLookup(t *testing.T) {
	r := NewRegistry()

	err := r.RegisterApply(ApplyHandler{
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

	h, ok := r.LookupApplyType("template")
	if !ok {
		t.Fatalf("expected apply handler lookup success")
	}
	if h.Type != "template" {
		t.Fatalf("expected normalized handler type, got %q", h.Type)
	}

	validateFn, ok := r.LookupApplyValidate("sshd")
	if !ok {
		t.Fatalf("expected validate lookup success")
	}
	if err := validateFn(ApplyContext{}); err != nil {
		t.Fatalf("validate fn failed: %v", err)
	}
}

func TestRegistry_RegisterApplyErrors(t *testing.T) {
	var nilReg *Registry
	if err := nilReg.RegisterApply(ApplyHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewRegistry()
	err := r.RegisterApply(ApplyHandler{Apply: func(ApplyContext, profile.Step) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("expected missing type error, got %v", err)
	}

	err = r.RegisterApply(ApplyHandler{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing Apply func") {
		t.Fatalf("expected missing apply func error, got %v", err)
	}

	err = r.RegisterApply(ApplyHandler{
		Type: "x",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("register baseline handler failed: %v", err)
	}

	err = r.RegisterApply(ApplyHandler{
		Type: "x",
		Apply: func(ApplyContext, profile.Step) error {
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}

	r2 := NewRegistry()
	err = r2.RegisterApply(ApplyHandler{
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

	err = r2.RegisterApply(ApplyHandler{
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

	err = r2.RegisterApply(ApplyHandler{
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

	err = r2.RegisterApply(ApplyHandler{
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

func TestRegistry_ApplyLookupNilRegistry(t *testing.T) {
	var nilReg *Registry
	if _, ok := nilReg.LookupApplyType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
	if _, ok := nilReg.LookupApplyValidate("x"); ok {
		t.Fatalf("expected nil registry validate lookup miss")
	}
}

func TestRegistry_RegisterPlanAndLookup(t *testing.T) {
	r := NewRegistry()

	err := r.RegisterPlan(PlanHandler{
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

	h, ok := r.LookupPlanType("firewall")
	if !ok {
		t.Fatalf("expected plan handler lookup success")
	}
	got, err := h.Plan(PlanContext{}, profile.Step{})
	if err != nil || got.Summary != "ok" {
		t.Fatalf("unexpected plan call result: got=%+v err=%v", got, err)
	}

	validateFn, ok := r.LookupPlanValidate("  FIREWALL ")
	if !ok {
		t.Fatalf("expected plan validate lookup success")
	}
	validateResult, err := validateFn(PlanContext{})
	if err != nil || !strings.Contains(validateResult.Summary, "validate") {
		t.Fatalf("unexpected plan validate result: got=%+v err=%v", validateResult, err)
	}
}

func TestRegistry_RegisterPlanErrors(t *testing.T) {
	var nilReg *Registry
	if err := nilReg.RegisterPlan(PlanHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewRegistry()
	err := r.RegisterPlan(PlanHandler{})
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("expected missing type error, got %v", err)
	}

	err = r.RegisterPlan(PlanHandler{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing Plan func") {
		t.Fatalf("expected missing plan func error, got %v", err)
	}

	err = r.RegisterPlan(PlanHandler{
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

	err = r.RegisterPlan(PlanHandler{
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

	err = r.RegisterPlan(PlanHandler{
		Type: "x",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plan handler failed: %v", err)
	}

	err = r.RegisterPlan(PlanHandler{
		Type: "x",
		Plan: func(PlanContext, profile.Step) (PlanResult, error) {
			return PlanResult{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}

	err = r.RegisterPlan(PlanHandler{
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

	err = r.RegisterPlan(PlanHandler{
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

func TestRegistry_PlanLookupNilRegistry(t *testing.T) {
	var nilReg *Registry
	if _, ok := nilReg.LookupPlanType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
	if _, ok := nilReg.LookupPlanValidate("x"); ok {
		t.Fatalf("expected nil registry validate lookup miss")
	}
}

func TestRegistry_RegisterRollbackAndLookup(t *testing.T) {
	r := NewRegistry()

	err := r.RegisterRollback(RollbackHandler{
		Type: "  TEMPLATE  ",
		Capture: func(RollbackContext, profile.Step) (step StepRecord, err error) {
			return StepRecord{Type: "template"}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}

	h, ok := r.LookupRollbackType("template")
	if !ok {
		t.Fatalf("expected rollback handler lookup success")
	}
	if h.Type != "template" {
		t.Fatalf("expected normalized handler type, got %q", h.Type)
	}
}

func TestRegistry_RegisterRollbackErrors(t *testing.T) {
	var nilReg *Registry
	if err := nilReg.RegisterRollback(RollbackHandler{}); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("expected nil registry error, got %v", err)
	}

	r := NewRegistry()
	err := r.RegisterRollback(RollbackHandler{})
	if err == nil || !strings.Contains(err.Error(), "type is required") {
		t.Fatalf("expected missing type error, got %v", err)
	}

	err = r.RegisterRollback(RollbackHandler{Type: "x"})
	if err == nil || !strings.Contains(err.Error(), "missing Capture func") {
		t.Fatalf("expected missing capture func error, got %v", err)
	}

	err = r.RegisterRollback(RollbackHandler{
		Type: "x",
		Capture: func(RollbackContext, profile.Step) (StepRecord, error) {
			return StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}

	err = r.RegisterRollback(RollbackHandler{
		Type: "x",
		Capture: func(RollbackContext, profile.Step) (StepRecord, error) {
			return StepRecord{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected duplicate type error, got %v", err)
	}
}

func TestRegistry_RollbackLookupNilRegistry(t *testing.T) {
	var nilReg *Registry
	if _, ok := nilReg.LookupRollbackType("x"); ok {
		t.Fatalf("expected nil registry type lookup miss")
	}
}

func TestRegistry_RegisterBundle(t *testing.T) {
	r := NewRegistry()
	err := r.RegisterBundle(validPluginBundle("x"))
	if err != nil {
		t.Fatalf("register bundle failed: %v", err)
	}
	if _, ok := r.LookupApplyType("x"); !ok {
		t.Fatal("expected apply handler from bundle")
	}
	if _, ok := r.LookupPlanType("x"); !ok {
		t.Fatal("expected plan handler from bundle")
	}
	if _, ok := r.LookupRollbackType("x"); !ok {
		t.Fatal("expected rollback handler from bundle")
	}
}

func TestRegistry_RegisterBundleErrors(t *testing.T) {
	t.Run("nil registry", func(t *testing.T) {
		var nilReg *Registry
		if err := nilReg.RegisterBundle(validPluginBundle("x")); err == nil || !strings.Contains(err.Error(), "nil") {
			t.Fatalf("expected nil registry error, got %v", err)
		}
	})

	t.Run("missing plan handler for type", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.PlanHandlers = nil
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "at least one plan handler") {
			t.Fatalf("expected missing plan error, got %v", err)
		}
	})

	t.Run("missing rollback handler for type", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.RollbackHandlers = nil
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "at least one rollback handler") {
			t.Fatalf("expected missing rollback error, got %v", err)
		}
	})

	t.Run("type mismatch coverage", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.PlanHandlers[0].Type = "y"
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "missing plan handler") {
			t.Fatalf("expected type coverage error, got %v", err)
		}
	})

	t.Run("missing apply validate kinds", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.ApplyHandlers[0].ValidateKinds = nil
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "must define at least one validate kind") {
			t.Fatalf("expected apply validate error, got %v", err)
		}
	})

	t.Run("missing plan validate kinds", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.PlanHandlers[0].ValidateKinds = nil
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "must define at least one validate kind") {
			t.Fatalf("expected plan validate error, got %v", err)
		}
	})

	t.Run("validate kind parity mismatch", func(t *testing.T) {
		r := NewRegistry()
		bundle := validPluginBundle("x")
		bundle.PlanHandlers[0].ValidateKinds = map[string]func(PlanContext) (PlanResult, error){
			"other-validate": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
		}
		err := r.RegisterBundle(bundle)
		if err == nil || !strings.Contains(err.Error(), "missing plan validate kind") {
			t.Fatalf("expected validate parity error, got %v", err)
		}
	})

	t.Run("bundle registration is atomic on failure", func(t *testing.T) {
		r := NewRegistry()
		if err := r.RegisterBundle(validPluginBundle("x")); err != nil {
			t.Fatalf("seed bundle failed: %v", err)
		}

		bad := validPluginBundle("y")
		// Force validate-kind collision with existing registry state.
		bad.ApplyHandlers[0].ValidateKinds = map[string]func(ApplyContext) error{
			"x-validate": func(ApplyContext) error { return nil },
		}
		bad.PlanHandlers[0].ValidateKinds = map[string]func(PlanContext) (PlanResult, error){
			"x-validate": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
		}
		err := r.RegisterBundle(bad)
		if err == nil || !strings.Contains(err.Error(), "already registered") {
			t.Fatalf("expected collision error, got %v", err)
		}

		if _, ok := r.LookupApplyType("y"); ok {
			t.Fatal("unexpected partial apply registration for failed bundle")
		}
		if _, ok := r.LookupPlanType("y"); ok {
			t.Fatal("unexpected partial plan registration for failed bundle")
		}
		if _, ok := r.LookupRollbackType("y"); ok {
			t.Fatal("unexpected partial rollback registration for failed bundle")
		}
	})
}

func validPluginBundle(typ string) PluginBundle {
	return PluginBundle{
		ApplyHandlers: []ApplyHandler{{
			Type: typ,
			Apply: func(ApplyContext, profile.Step) error {
				return nil
			},
			ValidateKinds: map[string]func(ApplyContext) error{
				typ + "-validate": func(ApplyContext) error { return nil },
			},
		}},
		PlanHandlers: []PlanHandler{{
			Type: typ,
			Plan: func(PlanContext, profile.Step) (PlanResult, error) {
				return PlanResult{}, nil
			},
			ValidateKinds: map[string]func(PlanContext) (PlanResult, error){
				typ + "-validate": func(PlanContext) (PlanResult, error) { return PlanResult{}, nil },
			},
		}},
		RollbackHandlers: []RollbackHandler{{
			Type: typ,
			Capture: func(RollbackContext, profile.Step) (StepRecord, error) {
				return StepRecord{}, nil
			},
		}},
	}
}
