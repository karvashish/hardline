package template

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApplyHandler(t *testing.T) {
	validated := false
	h := ApplyHandler(
		func(_ pluginapi.ApplyContext, _ *profile.TemplateSpec) error { return nil },
		func(pluginapi.ApplyContext) error {
			validated = true
			return nil
		},
	)
	if h.Type != "template" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if _, ok := h.ValidateKinds["sshd"]; !ok {
		t.Fatal("expected sshd validate handler")
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "template"}); err == nil || !strings.Contains(err.Error(), "template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "template", Template: &profile.TemplateSpec{Src: "x", Dest: "y"}}); err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
	if err := h.ValidateKinds["sshd"](pluginapi.ApplyContext{}); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
	if !validated {
		t.Fatal("expected validate callback invocation")
	}

	hNoValidate := ApplyHandler(func(_ pluginapi.ApplyContext, _ *profile.TemplateSpec) error { return nil }, nil)
	if hNoValidate.ValidateKinds != nil {
		t.Fatalf("expected nil validate map when callback is nil, got %#v", hNoValidate.ValidateKinds)
	}
}

func TestPlanHandler(t *testing.T) {
	validated := false
	h := PlanHandler(
		func(_ pluginapi.PlanContext, _ *profile.TemplateSpec) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{Summary: "ok", Noop: 2}, nil
		},
		func(pluginapi.PlanContext) (pluginapi.PlanResult, error) {
			validated = true
			return pluginapi.PlanResult{Summary: "validated", Noop: 2}, nil
		},
	)
	if h.Type != "template" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if _, ok := h.ValidateKinds["sshd"]; !ok {
		t.Fatal("expected sshd validate handler")
	}
	if _, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "template"}); err == nil || !strings.Contains(err.Error(), "template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	res, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "template", Template: &profile.TemplateSpec{Src: "x", Dest: "y"}})
	if err != nil {
		t.Fatalf("unexpected plan error: %v", err)
	}
	if res.Summary != "ok" {
		t.Fatalf("unexpected plan summary: %q", res.Summary)
	}
	vRes, err := h.ValidateKinds["sshd"](pluginapi.PlanContext{})
	if err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
	if vRes.Summary != "validated" || !validated {
		t.Fatalf("expected validate callback result, got=%+v validated=%v", vRes, validated)
	}

	hNoValidate := PlanHandler(func(_ pluginapi.PlanContext, _ *profile.TemplateSpec) (pluginapi.PlanResult, error) {
		return pluginapi.PlanResult{}, nil
	}, nil)
	if hNoValidate.ValidateKinds != nil {
		t.Fatalf("expected nil validate map when callback is nil, got %#v", hNoValidate.ValidateKinds)
	}
}
