package plan

import (
	"errors"
	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"os"
	"strings"
	"testing"
)

func TestRegisterPlanActionAndPlanStep(t *testing.T) {
	prev := planPluginRegistry
	defer func() {
		planPluginRegistry = prev
	}()
	planPluginRegistry = pluginapi.NewRegistry()

	calledPlan := false
	calledValidate := false
	err := RegisterPlanAction(pluginapi.PlanHandler{
		Type: "fake",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			calledPlan = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected profile in plan context: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step in plan handler: %+v", s)
			}
			return pluginapi.PlanResult{Summary: "fake summary", Details: []string{"detail"}, Noop: 1}, nil
		},
		ValidateKinds: map[string]func(pluginapi.PlanContext) (pluginapi.PlanResult, error){
			"vk": func(ctx pluginapi.PlanContext) (pluginapi.PlanResult, error) {
				calledValidate = true
				if ctx.Inspector == nil {
					t.Fatal("expected inspector in validate context")
				}
				return pluginapi.PlanResult{Summary: "validate summary", Details: []string{"vdetail"}, Noop: 2}, nil
			},
		},
	})
	if err != nil {
		t.Fatalf("register fake handler failed: %v", err)
	}

	err = RegisterPlanAction(pluginapi.PlanHandler{
		Type: "fake0",
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{Summary: "noop0", Noop: 0}, nil
		},
	})
	if err != nil {
		t.Fatalf("register fake0 handler failed: %v", err)
	}

	err = RegisterPlanAction(pluginapi.PlanHandler{
		Type: "boom",
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, errors.New("plan boom")
		},
	})
	if err != nil {
		t.Fatalf("register boom handler failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	insp := stubInspector{}

	sp, err := planStep(insp, p, profile.Step{ID: "s1", Type: "fake", Severity: "high", RiskClass: "r"})
	if err != nil {
		t.Fatalf("planStep fake failed: %v", err)
	}
	if !calledPlan {
		t.Fatal("expected fake plan handler to be called")
	}
	if sp.Summary != "fake summary" || sp.Severity != "medium" || len(sp.Details) != 1 {
		t.Fatalf("unexpected step plan from fake: %+v", sp)
	}

	sp0, err := planStep(insp, p, profile.Step{ID: "s0", Type: "fake0", Severity: "high"})
	if err != nil {
		t.Fatalf("planStep fake0 failed: %v", err)
	}
	if sp0.Severity != "low" {
		t.Fatalf("expected severity low for noop=0, got %+v", sp0)
	}

	spUnknown, err := planStep(insp, p, profile.Step{ID: "u", Type: "unknown", Severity: "high"})
	if err != nil {
		t.Fatalf("planStep unknown failed: %v", err)
	}
	if !strings.Contains(spUnknown.Summary, "unknown or empty step type") {
		t.Fatalf("unexpected unknown step summary: %+v", spUnknown)
	}

	if _, err := planStep(insp, p, profile.Step{ID: "b", Type: "boom"}); err == nil || !strings.Contains(err.Error(), "plan boom") {
		t.Fatalf("expected boom error, got %v", err)
	}

	if _, err := planStep(insp, p, profile.Step{ID: "v0", Type: "validate"}); err == nil || !strings.Contains(err.Error(), "validate spec missing") {
		t.Fatalf("expected validate missing error, got %v", err)
	}

	spValidate, err := planStep(insp, p, profile.Step{ID: "v1", Type: "validate", Validate: "vk"})
	if err != nil {
		t.Fatalf("validate step failed: %v", err)
	}
	if !calledValidate || spValidate.Summary != "validate summary" {
		t.Fatalf("unexpected validate plan result: %+v", spValidate)
	}

	summary, details, err := planValidate(insp, "missing-kind")
	if err != nil {
		t.Fatalf("unsupported validate should not fail: %v", err)
	}
	if !strings.Contains(summary, "unsupported kind") || len(details) == 0 {
		t.Fatalf("unexpected unsupported validate output: summary=%q details=%v", summary, details)
	}

	summary, details, err = planValidate(insp, "vk")
	if err != nil {
		t.Fatalf("supported validate failed: %v", err)
	}
	if summary != "validate summary" || len(details) != 1 {
		t.Fatalf("unexpected supported validate output: summary=%q details=%v", summary, details)
	}
}

func TestNewDefaultPlanRegistry(t *testing.T) {
	r := newDefaultPlanRegistry()

	for _, typ := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		if _, ok := r.LookupPlanType(typ); !ok {
			t.Fatalf("missing default plan handler %q", typ)
		}
	}

	insp := stubInspector{}
	ctx := planActionContext(insp, &profile.Profile{ID: "p2"})
	if ctx.Profile == nil || ctx.Profile.ID != "p2" {
		t.Fatalf("unexpected plan action context profile: %+v", ctx.Profile)
	}

	cases := []profile.Step{
		{ID: "p", Type: "packages", Packages: &profile.PackageSpec{}},
		{ID: "t", Type: "template", Template: &profile.TemplateSpec{Src: "x", Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}},
		{ID: "s", Type: "service", Service: &profile.ServiceSpec{Name: "ssh", State: "started"}},
		{ID: "f", Type: "firewall", Firewall: &profile.FirewallSpec{Backend: "ufw"}},
		{ID: "ft", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{Backend: "ufw"}},
	}
	for _, step := range cases {
		h, _ := r.LookupPlanType(step.Type)
		_, _ = h.Plan(ctx, step)
	}

	if validateSSHD, ok := r.LookupPlanValidate("sshd"); ok {
		if _, err := validateSSHD(planActionContext(insp, nil)); err != nil {
			t.Fatalf("default sshd validate failed: %v", err)
		}
	} else {
		t.Fatal("missing default sshd validate handler")
	}

	if validateFW, ok := r.LookupPlanValidate("firewall"); ok {
		if _, err := validateFW(planActionContext(insp, nil)); err != nil {
			t.Fatalf("default firewall validate failed: %v", err)
		}
	} else {
		t.Fatal("missing default firewall validate handler")
	}
}

type stubInspector struct{}

func (stubInspector) PackageInstalled(string) bool { return false }

func (stubInspector) AptAutoremovePreview() ([]string, error) { return nil, nil }

func (stubInspector) AptUpgradePreview() ([]string, error) { return nil, nil }

func (stubInspector) AptInstallPreview([]string) ([]string, error) { return nil, nil }

func (stubInspector) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (stubInspector) ReadRootFile(string) (string, error) { return "", nil }

func (stubInspector) IsServiceEnabled(string) bool { return false }

func (stubInspector) IsServiceActive(string) bool { return false }

func (stubInspector) SSHIncludePresent() bool { return true }

func (stubInspector) SSHConfigTest() error { return nil }

func (stubInspector) FirewallIncludePresent() bool { return true }

func (stubInspector) FirewallConfigTest() error { return nil }

func (stubInspector) FirewallAllowedPorts() (map[string][]int, error) { return map[string][]int{}, nil }

func (stubInspector) FirewallPolicySummary() ([]string, error) { return nil, nil }

func (stubInspector) FirewallOtherManagers() ([]string, error) { return nil, nil }

func (stubInspector) FirewallOnDiskPolicySummary(string) ([]string, error) { return nil, nil }

func (stubInspector) FirewallHasStatefulBaseline() (bool, error) { return true, nil }

func (stubInspector) FirewallHasDefaultDropInput() (bool, error) { return true, nil }

func (stubInspector) FirewallAllowedPortsDetailed() ([]inspector.FirewallRuleInfo, error) {
	return nil, nil
}
