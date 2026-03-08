package builtin

import (
	"errors"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"os"
	"strings"
	"testing"
)

func TestDefaultApplyHandlers(t *testing.T) {
	runRootCalls := 0
	handlers := DefaultApplyHandlers(ApplyDeps{
		RunRoot: func(_ *ssh.Client, _ string) error {
			runRootCalls++
			return nil
		},
		NewSFTPClient:     func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
		WriteRootFile:     func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
		MarkServiceDirty:  func(string) {},
		IsServiceDirty:    func(string) bool { return false },
		ClearServiceDirty: func(string) {},
	})

	if len(handlers) != 5 {
		t.Fatalf("expected 5 apply handlers, got %d", len(handlers))
	}

	byType := map[string]pluginapi.ApplyHandler{}
	for _, h := range handlers {
		byType[h.Type] = h
	}
	for _, typ := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		if _, ok := byType[typ]; !ok {
			t.Fatalf("missing apply handler for type %q", typ)
		}
	}

	if err := byType["packages"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:       "p",
		Type:     "packages",
		Packages: &profile.PackageSpec{Update: true},
	}); err != nil {
		t.Fatalf("packages apply failed: %v", err)
	}

	if err := byType["template"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:   "t",
		Type: "template",
		Template: &profile.TemplateSpec{
			Src:  "templates/sshd-hardening.tmpl",
			Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
		},
	}); err == nil || !strings.Contains(err.Error(), "profile context is required") {
		t.Fatalf("expected template context error, got %v", err)
	}

	if err := byType["service"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:   "s",
		Type: "service",
		Service: &profile.ServiceSpec{
			Name:  "ssh",
			State: "started",
		},
	}); err != nil {
		t.Fatalf("service apply failed: %v", err)
	}

	if err := byType["firewall"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:   "f",
		Type: "firewall",
		Firewall: &profile.FirewallSpec{
			Backend: "ufw",
		},
	}); err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Fatalf("expected firewall backend error, got %v", err)
	}

	if err := byType["firewall_template"].Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:   "ft",
		Type: "firewall_template",
		FirewallTemplate: &profile.FirewallTemplateSpec{
			Backend: "ufw",
		},
	}); err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
		t.Fatalf("expected firewall_template backend error, got %v", err)
	}

	templateValidate, ok := byType["template"].ValidateKinds["sshd"]
	if !ok {
		t.Fatal("expected template validate kind sshd")
	}
	if err := templateValidate(pluginapi.ApplyContext{}); err != nil {
		t.Fatalf("template validate failed: %v", err)
	}

	firewallValidate, ok := byType["firewall"].ValidateKinds["firewall"]
	if !ok {
		t.Fatal("expected firewall validate kind firewall")
	}
	if err := firewallValidate(pluginapi.ApplyContext{}); err != nil {
		t.Fatalf("firewall validate failed: %v", err)
	}

	if _, ok := byType["packages"].ValidateKinds["packages"]; !ok {
		t.Fatal("expected packages validate kind packages")
	}
	if _, ok := byType["service"].ValidateKinds["service"]; !ok {
		t.Fatal("expected service validate kind service")
	}
	if _, ok := byType["firewall_template"].ValidateKinds["firewall_template"]; !ok {
		t.Fatal("expected firewall_template validate kind firewall_template")
	}

	if runRootCalls == 0 {
		t.Fatal("expected runRoot to be used")
	}
}

func TestDefaultPlanHandlers(t *testing.T) {
	handlers := DefaultPlanHandlers()
	if len(handlers) != 5 {
		t.Fatalf("expected 5 plan handlers, got %d", len(handlers))
	}

	byType := map[string]pluginapi.PlanHandler{}
	for _, h := range handlers {
		byType[h.Type] = h
	}
	for _, typ := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		if _, ok := byType[typ]; !ok {
			t.Fatalf("missing plan handler for type %q", typ)
		}
	}

	ctx := pluginapi.PlanContext{Inspector: stubInspector{}}

	if _, err := byType["packages"].Plan(ctx, profile.Step{
		ID:       "p",
		Type:     "packages",
		Packages: &profile.PackageSpec{},
	}); err != nil {
		t.Fatalf("packages plan failed: %v", err)
	}

	if _, err := byType["template"].Plan(ctx, profile.Step{
		ID:   "t",
		Type: "template",
		Template: &profile.TemplateSpec{
			Src:  "templates/sshd-hardening.tmpl",
			Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
		},
	}); err == nil || !strings.Contains(err.Error(), "profile context is required") {
		t.Fatalf("expected template context error, got %v", err)
	}

	if _, err := byType["service"].Plan(ctx, profile.Step{
		ID:   "s",
		Type: "service",
		Service: &profile.ServiceSpec{
			Name:  "ssh",
			State: "started",
		},
	}); err != nil {
		t.Fatalf("service plan failed: %v", err)
	}

	if _, err := byType["firewall"].Plan(ctx, profile.Step{
		ID:   "f",
		Type: "firewall",
		Firewall: &profile.FirewallSpec{
			Backend: "ufw",
		},
	}); err != nil {
		t.Fatalf("firewall plan failed: %v", err)
	}

	if _, err := byType["firewall_template"].Plan(ctx, profile.Step{
		ID:   "ft",
		Type: "firewall_template",
		FirewallTemplate: &profile.FirewallTemplateSpec{
			Backend: "ufw",
		},
	}); err != nil {
		t.Fatalf("firewall_template plan failed: %v", err)
	}

	templateValidate, ok := byType["template"].ValidateKinds["sshd"]
	if !ok {
		t.Fatal("expected template validate kind sshd")
	}
	if _, err := templateValidate(ctx); err != nil {
		t.Fatalf("template validate plan failed: %v", err)
	}

	firewallValidate, ok := byType["firewall"].ValidateKinds["firewall"]
	if !ok {
		t.Fatal("expected firewall validate kind firewall")
	}
	if _, err := firewallValidate(ctx); err != nil {
		t.Fatalf("firewall validate plan failed: %v", err)
	}

	if _, ok := byType["packages"].ValidateKinds["packages"]; !ok {
		t.Fatal("expected packages validate kind packages")
	}
	if _, ok := byType["service"].ValidateKinds["service"]; !ok {
		t.Fatal("expected service validate kind service")
	}
	if _, ok := byType["firewall_template"].ValidateKinds["firewall_template"]; !ok {
		t.Fatal("expected firewall_template validate kind firewall_template")
	}
}

func TestDefaultRollbackHandlers(t *testing.T) {
	handlers := DefaultRollbackHandlers(RollbackDeps{
		RunRoot:           func(*ssh.Client, string) error { return nil },
		RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil },
		ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
	})

	if len(handlers) != 5 {
		t.Fatalf("expected 5 rollback handlers, got %d", len(handlers))
	}

	byType := map[string]pluginapi.RollbackHandler{}
	for _, h := range handlers {
		byType[h.Type] = h
	}
	for _, typ := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		if _, ok := byType[typ]; !ok {
			t.Fatalf("missing rollback handler for type %q", typ)
		}
	}

	_, err := byType["packages"].Capture(pluginapi.RollbackContext{}, profile.Step{ID: "p", Type: "packages"})
	if err == nil || !strings.Contains(err.Error(), "packages spec missing") {
		t.Fatalf("expected packages missing spec error, got %v", err)
	}

	_, err = byType["template"].Capture(pluginapi.RollbackContext{}, profile.Step{ID: "t", Type: "template"})
	if err == nil || !strings.Contains(err.Error(), "template spec missing") {
		t.Fatalf("expected template missing spec error, got %v", err)
	}

	_, err = byType["service"].Capture(pluginapi.RollbackContext{}, profile.Step{ID: "s", Type: "service"})
	if err == nil || !strings.Contains(err.Error(), "service spec missing") {
		t.Fatalf("expected service missing spec error, got %v", err)
	}

	_, err = byType["firewall"].Capture(pluginapi.RollbackContext{}, profile.Step{ID: "f", Type: "firewall"})
	if err == nil || !strings.Contains(err.Error(), "firewall spec missing") {
		t.Fatalf("expected firewall missing spec error, got %v", err)
	}

	_, err = byType["firewall_template"].Capture(pluginapi.RollbackContext{}, profile.Step{ID: "ft", Type: "firewall_template"})
	if err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected firewall_template missing spec error, got %v", err)
	}
}

func TestDefaultBundle(t *testing.T) {
	bundle := DefaultBundle(
		ApplyDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			NewSFTPClient:     func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile:     func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
			MarkServiceDirty:  func(string) {},
			IsServiceDirty:    func(string) bool { return false },
			ClearServiceDirty: func(string) {},
		},
		RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
		},
	)

	reg := pluginapi.NewRegistry()
	if err := reg.RegisterBundle(bundle); err != nil {
		t.Fatalf("register default bundle failed: %v", err)
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

func (stubInspector) FirewallAllowedPortsDetailed() ([]pluginapi.FirewallRuleInfo, error) {
	return nil, nil
}
