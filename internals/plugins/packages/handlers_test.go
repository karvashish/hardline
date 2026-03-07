package packages

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApplyHandler(t *testing.T) {
	h := ApplyHandler(func(_ pluginapi.ApplyContext, spec *profile.PackageSpec) error {
		if spec == nil {
			t.Fatal("spec should not be nil")
		}
		return nil
	})
	if h.Type != "packages" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "packages"}); err == nil || !strings.Contains(err.Error(), "packages spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	if err := h.Apply(pluginapi.ApplyContext{}, profile.Step{ID: "x", Type: "packages", Packages: &profile.PackageSpec{}}); err != nil {
		t.Fatalf("unexpected apply error: %v", err)
	}
}

func TestPlanHandler(t *testing.T) {
	h := PlanHandler(func(_ pluginapi.PlanContext, _ *profile.PackageSpec) (pluginapi.PlanResult, error) {
		return pluginapi.PlanResult{Summary: "ok", Noop: 2}, nil
	})
	if h.Type != "packages" {
		t.Fatalf("unexpected type: %q", h.Type)
	}
	if _, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "packages"}); err == nil || !strings.Contains(err.Error(), "packages spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}
	res, err := h.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "packages", Packages: &profile.PackageSpec{}})
	if err != nil {
		t.Fatalf("unexpected plan error: %v", err)
	}
	if res.Summary != "ok" {
		t.Fatalf("unexpected plan summary: %q", res.Summary)
	}

	hErr := PlanHandler(func(_ pluginapi.PlanContext, _ *profile.PackageSpec) (pluginapi.PlanResult, error) {
		return pluginapi.PlanResult{}, errors.New("boom")
	})
	if _, err := hErr.Plan(pluginapi.PlanContext{}, profile.Step{ID: "x", Type: "packages", Packages: &profile.PackageSpec{}}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected boom error, got %v", err)
	}
}
