package plan

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestRegisterPluginAndPlanStep(t *testing.T) {
	prev := planPluginRegistry
	defer func() { planPluginRegistry = prev }()

	planPluginRegistry = pluginapi.NewRegistry()

	called := false
	err := RegisterPlugin(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected profile in plan context: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step in plan handler: %+v", s)
			}
			return pluginapi.PlanResult{Summary: "fake summary", Details: []string{"detail"}, Noop: 1}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	insp := stubInspector{}

	sp, err := planStep(insp, p, profile.Step{ID: "s1", Plugin: "fake", Severity: "high", RiskClass: "r"})
	if err != nil {
		t.Fatalf("planStep fake failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plan handler to be called")
	}
	if sp.Summary != "fake summary" || sp.Severity != "high" || len(sp.Details) != 1 {
		t.Fatalf("unexpected step plan from fake: %+v", sp)
	}
}

func TestPlanStep_UnknownPlugin(t *testing.T) {
	sp, err := planStep(stubInspector{}, &profile.Profile{}, profile.Step{ID: "u", Plugin: "unknown"})
	if err != nil {
		t.Fatalf("planStep unknown failed: %v", err)
	}
	if !strings.Contains(sp.Summary, "unknown or empty plugin") {
		t.Fatalf("unexpected unknown step summary: %+v", sp)
	}
}

func TestPlanStep_ValidationPolicy(t *testing.T) {
	prev := planPluginRegistry
	defer func() { planPluginRegistry = prev }()

	planPluginRegistry = pluginapi.NewRegistry()
	err := RegisterPlugin(pluginapi.Plugin{
		Name:               "external",
		InternalValidation: false,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register external plugin failed: %v", err)
	}

	_, err = planStep(stubInspector{}, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"})
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	sp, err := planStep(stubInspector{}, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	})
	if err != nil {
		t.Fatalf("expected allow_unvalidated plan success, got %v", err)
	}
	if len(sp.Details) == 0 || !strings.Contains(sp.Details[len(sp.Details)-1], "allow_unvalidated=true") {
		t.Fatalf("expected explicit unvalidated detail, got %+v", sp)
	}
}

func TestNewDefaultPlanRegistry(t *testing.T) {
	r := newDefaultPlanRegistry()

	for _, name := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		plugin, ok := r.Lookup(name)
		if !ok {
			t.Fatalf("missing default plan plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}
}

type stubInspector struct{}

func (stubInspector) PackageInstalled(string) bool                         { return false }
func (stubInspector) AptAutoremovePreview() ([]string, error)              { return nil, nil }
func (stubInspector) AptUpgradePreview() ([]string, error)                 { return nil, nil }
func (stubInspector) AptInstallPreview([]string) ([]string, error)         { return nil, nil }
func (stubInspector) Stat(string) (os.FileInfo, error)                     { return nil, errors.New("not found") }
func (stubInspector) ReadRootFile(string) (string, error)                  { return "", nil }
func (stubInspector) IsServiceEnabled(string) bool                         { return false }
func (stubInspector) IsServiceActive(string) bool                          { return false }
func (stubInspector) SSHIncludePresent() bool                              { return true }
func (stubInspector) SSHConfigTest() error                                 { return nil }
func (stubInspector) FirewallIncludePresent() bool                         { return true }
func (stubInspector) FirewallConfigTest() error                            { return nil }
func (stubInspector) FirewallAllowedPorts() (map[string][]int, error)      { return map[string][]int{}, nil }
func (stubInspector) FirewallPolicySummary() ([]string, error)             { return nil, nil }
func (stubInspector) FirewallOtherManagers() ([]string, error)             { return nil, nil }
func (stubInspector) FirewallOnDiskPolicySummary(string) ([]string, error) { return nil, nil }
func (stubInspector) FirewallHasStatefulBaseline() (bool, error)           { return true, nil }
func (stubInspector) FirewallHasDefaultDropInput() (bool, error)           { return true, nil }
func (stubInspector) FirewallAllowedPortsDetailed() ([]inspector.FirewallRuleInfo, error) {
	return nil, nil
}
