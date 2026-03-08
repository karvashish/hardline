package firewalltemplate

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApplyHandler(t *testing.T) {
	h := ApplyHandler(func(_ pluginapi.ApplyContext, _ *profile.FirewallTemplateSpec) error { return nil })
	if h.Type != "firewall_template" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "firewall_template"}); err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{Backend: "nftables"}}); err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
}

func TestPlanHandler(t *testing.T) {
	h := PlanHandler(func(_ pluginapi.PlanContext, _ *profile.FirewallTemplateSpec) (pluginapi.PlanResult, error) {
		return pluginapi.PlanResult{Summary: "ok", Noop: 2}, nil
	})
	if h.Type != "firewall_template" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if _, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "firewall_template"}); err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	res, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{Backend: "nftables"}})
	if err != nil {
		t.Fatalf("unexpected plan error: %v", err)
	}
	if res.Summary != "ok" {
		t.Fatalf("unexpected plan summary: %q", res.Summary)
	}
}

func TestDefaultHandlers_ValidateKinds(t *testing.T) {
	applyHandler := DefaultApplyHandler(ApplyDeps{})
	applyValidate, ok := applyHandler.ValidateKinds["firewall_template"]
	if !ok {
		t.Fatal("expected apply validate kind firewall_template")
	}
	if err := applyValidate(pluginapi.ApplyContext{}); err != nil {
		t.Fatalf("unexpected apply validate error: %v", err)
	}

	planHandler := DefaultPlanHandler()
	planValidate, ok := planHandler.ValidateKinds["firewall_template"]
	if !ok {
		t.Fatal("expected plan validate kind firewall_template")
	}
	result, err := planValidate(pluginapi.PlanContext{})
	if err != nil {
		t.Fatalf("unexpected plan validate error: %v", err)
	}
	if !strings.Contains(result.Summary, "no additional checks") {
		t.Fatalf("unexpected plan validate summary: %q", result.Summary)
	}
}
