package plan

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/profile"
)

type fakeInspector struct {
	installed map[string]bool

	upgradePreview    []string
	upgradePreviewErr error
	installPreview    []string
	installPreviewErr error
	autoremovePreview []string
	autoremoveErr     error

	statMap map[string]os.FileInfo
	statErr map[string]error

	serviceEnabled map[string]bool
	serviceActive  map[string]bool

	sshInclude bool
	sshTestErr error

	firewallInclude bool
	firewallTestErr error
}

func newFakeInspector() *fakeInspector {
	return &fakeInspector{
		installed:      map[string]bool{},
		statMap:        map[string]os.FileInfo{},
		statErr:        map[string]error{},
		serviceEnabled: map[string]bool{},
		serviceActive:  map[string]bool{},
	}
}

func (f *fakeInspector) PackageInstalled(name string) bool {
	return f.installed[name]
}

func (f *fakeInspector) AptAutoremovePreview() ([]string, error) {
	return f.autoremovePreview, f.autoremoveErr
}

func (f *fakeInspector) AptUpgradePreview() ([]string, error) {
	return f.upgradePreview, f.upgradePreviewErr
}

func (f *fakeInspector) AptInstallPreview(_ []string) ([]string, error) {
	return f.installPreview, f.installPreviewErr
}

func (f *fakeInspector) Stat(path string) (os.FileInfo, error) {
	if err, ok := f.statErr[path]; ok {
		return nil, err
	}
	if info, ok := f.statMap[path]; ok {
		return info, nil
	}
	return nil, os.ErrNotExist
}

func (f *fakeInspector) ReadRootFile(_ string) (string, error) {
	return "", nil
}

func (f *fakeInspector) IsServiceEnabled(unit string) bool {
	return f.serviceEnabled[unit]
}

func (f *fakeInspector) IsServiceActive(unit string) bool {
	return f.serviceActive[unit]
}

func (f *fakeInspector) SSHIncludePresent() bool {
	return f.sshInclude
}

func (f *fakeInspector) SSHConfigTest() error {
	return f.sshTestErr
}

func (f *fakeInspector) FirewallIncludePresent() bool {
	return f.firewallInclude
}

func (f *fakeInspector) FirewallConfigTest() error {
	return f.firewallTestErr
}

func (f *fakeInspector) FirewallAllowedPorts() (map[string][]int, error) {
	return map[string][]int{}, nil
}

func (f *fakeInspector) FirewallPolicySummary() ([]string, error) {
	return nil, nil
}

func (f *fakeInspector) FirewallOtherManagers() ([]string, error) {
	return nil, nil
}

func (f *fakeInspector) FirewallOnDiskPolicySummary(_ string) ([]string, error) {
	return nil, nil
}

func (f *fakeInspector) FirewallHasStatefulBaseline() (bool, error) {
	return false, nil
}

func (f *fakeInspector) FirewallHasDefaultDropInput() (bool, error) {
	return false, nil
}

func (f *fakeInspector) FirewallAllowedPortsDetailed() ([]inspector.FirewallRuleInfo, error) {
	return nil, nil
}

type fakeFileInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func TestPlanStep_DispatchAndSeverity(t *testing.T) {
	insp := newFakeInspector()

	cases := []struct {
		name    string
		step    profile.Step
		wantSub string
	}{
		{name: "packages missing", step: profile.Step{ID: "a", Type: "packages"}, wantSub: "packages spec missing"},
		{name: "template missing", step: profile.Step{ID: "b", Type: "template"}, wantSub: "template spec missing"},
		{name: "service missing", step: profile.Step{ID: "c", Type: "service"}, wantSub: "service spec missing"},
		{name: "firewall missing", step: profile.Step{ID: "d", Type: "firewall"}, wantSub: "firewall spec missing"},
		{name: "firewall_template missing", step: profile.Step{ID: "e", Type: "firewall_template"}, wantSub: "firewall_template spec missing"},
		{name: "validate missing", step: profile.Step{ID: "f", Type: "validate"}, wantSub: "validate spec missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := planStep(insp, tc.step)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q, got %v", tc.wantSub, err)
			}
		})
	}

	noopPlan, err := planStep(insp, profile.Step{
		ID:       "noop",
		Type:     "packages",
		Severity: "critical",
		Packages: &profile.PackageSpec{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if noopPlan.Severity != "low" {
		t.Fatalf("expected noop package severity override to low, got %q", noopPlan.Severity)
	}

	updatePlan, err := planStep(insp, profile.Step{
		ID:       "upd",
		Type:     "packages",
		Severity: "critical",
		Packages: &profile.PackageSpec{Update: true},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if updatePlan.Severity != "medium" {
		t.Fatalf("expected update-only package severity override to medium, got %q", updatePlan.Severity)
	}

	unknownPlan, err := planStep(insp, profile.Step{ID: "u", Type: "unknown"})
	if err != nil {
		t.Fatalf("unknown step should not error: %v", err)
	}
	if !strings.Contains(unknownPlan.Summary, "unknown or empty step type") {
		t.Fatalf("unexpected unknown summary: %q", unknownPlan.Summary)
	}

	insp = newFakeInspector()
	insp.statMap["/etc/example.conf"] = fakeFileInfo{name: "example.conf", size: 10, mode: 0o644}
	insp.statMap["/etc/nftables.d/99-hardline-firewall.nft"] = fakeFileInfo{name: "99-hardline-firewall.nft", size: 64, mode: 0o644}
	insp.firewallInclude = true
	insp.sshInclude = true
	on := true

	successCases := []profile.Step{
		{
			ID:       "tmpl",
			Type:     "template",
			Template: &profile.TemplateSpec{Src: "templates/x.tmpl", Dest: "/etc/example.conf", Mode: "0644"},
		},
		{
			ID:      "svc",
			Type:    "service",
			Service: &profile.ServiceSpec{Name: "cron", Enabled: &on, State: "start"},
		},
		{
			ID:   "fw",
			Type: "firewall",
			Firewall: &profile.FirewallSpec{
				Backend:     "nftables",
				Family:      "inet",
				Table:       "filter",
				ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
				Policies:    []profile.FirewallPolicy{{Chain: "input", Policy: "drop"}},
				Rules:       []profile.FirewallRule{{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"}},
			},
		},
		{
			ID:   "fwt",
			Type: "firewall_template",
			FirewallTemplate: &profile.FirewallTemplateSpec{
				Backend:      "nftables",
				TemplateSrc:  "templates/fw.tmpl",
				TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft",
			},
		},
		{
			ID:       "val",
			Type:     "validate",
			Validate: "sshd",
		},
	}
	for _, step := range successCases {
		got, err := planStep(insp, step)
		if err != nil {
			t.Fatalf("planStep success case %q failed: %v", step.ID, err)
		}
		if got.StepID != step.ID {
			t.Fatalf("unexpected step id in plan: got=%q want=%q", got.StepID, step.ID)
		}
	}
}

func TestPlanPackages(t *testing.T) {
	insp := newFakeInspector()
	insp.installed["curl"] = true
	insp.installed["oldpkg"] = true
	insp.upgradePreview = []string{"openssl"}
	insp.installPreview = []string{"nginx", "nginx-common"}
	insp.autoremovePreview = []string{"unused-lib"}

	summary, details, noop, err := planPackages(insp, &profile.PackageSpec{
		Update:     true,
		Upgrade:    true,
		Install:    []string{"curl", "nginx"},
		Purge:      []string{"oldpkg", "not-installed"},
		Autoremove: true,
	})
	if err != nil {
		t.Fatalf("planPackages failed: %v", err)
	}
	if noop != 2 {
		t.Fatalf("expected changing plan noop=2, got %d", noop)
	}
	assertContains(t, summary, "update package index")
	assertContains(t, summary, "upgrade:")
	assertContains(t, summary, "install: nginx")
	assertContains(t, summary, "install dependencies: nginx-common")
	assertContains(t, summary, "purge: oldpkg")
	assertContains(t, summary, "autoremove unused packages")
	if len(details) == 0 {
		t.Fatal("expected non-empty package details")
	}

	insp = newFakeInspector()
	insp.installed["x"] = true
	insp.upgradePreviewErr = errors.New("upgrade fail")
	insp.installPreviewErr = errors.New("install fail")
	insp.autoremoveErr = errors.New("autoremove fail")
	summary, details, noop, err = planPackages(insp, &profile.PackageSpec{
		Upgrade:    true,
		Install:    []string{"x"},
		Autoremove: true,
	})
	if err != nil {
		t.Fatalf("planPackages should not fail on preview errors: %v", err)
	}
	if noop != 0 {
		t.Fatalf("expected noop=0 with only preview errors and no deterministic deltas, got %d", noop)
	}
	assertContains(t, summary, "no-op")
	assertContains(t, strings.Join(details, "\n"), "failed to preview upgrades")
	assertContains(t, strings.Join(details, "\n"), "failed to preview dependency installs")
	assertContains(t, strings.Join(details, "\n"), "failed to preview packages to be removed")
}

func TestPlanTemplate(t *testing.T) {
	insp := newFakeInspector()
	dest := "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"
	summary, details, err := planTemplate(insp, &profile.TemplateSpec{
		Src:  "templates/ssh.tmpl",
		Dest: dest,
		Mode: "",
	})
	if err != nil {
		t.Fatalf("planTemplate failed: %v", err)
	}
	assertContains(t, summary, "render")
	assertContains(t, strings.Join(details, "\n"), "does not exist")
	assertContains(t, strings.Join(details, "\n"), "0600 (default in executor)")
	assertContains(t, strings.Join(details, "\n"), "affects SSH daemon configuration")

	insp.statMap["/etc/nftables.d/99-hardline-firewall.nft"] = fakeFileInfo{name: "99-hardline-firewall.nft", size: 42, mode: 0o644}
	_, details, err = planTemplate(insp, &profile.TemplateSpec{
		Src:  "templates/fw.tmpl",
		Dest: "/etc/nftables.d/99-hardline-firewall.nft",
		Mode: "0644",
	})
	if err != nil {
		t.Fatalf("planTemplate failed: %v", err)
	}
	assertContains(t, strings.Join(details, "\n"), "exists")
	assertContains(t, strings.Join(details, "\n"), "affects nftables firewall configuration")
}

func TestPlanService(t *testing.T) {
	insp := newFakeInspector()
	if _, _, err := planService(insp, &profile.ServiceSpec{}); err == nil {
		t.Fatal("expected missing service name error")
	}

	insp.serviceEnabled["ssh"] = false
	insp.serviceActive["ssh"] = true
	enabled := true
	summary, details, err := planService(insp, &profile.ServiceSpec{
		Name:    "sshd",
		Enabled: &enabled,
		State:   "restart",
	})
	if err != nil {
		t.Fatalf("planService failed: %v", err)
	}
	assertContains(t, summary, "enable ssh at boot")
	assertContains(t, summary, "restart ssh")
	assertContains(t, strings.Join(details, "\n"), "desired:")

	summary, _, err = planService(insp, &profile.ServiceSpec{Name: "cron", State: "bogus"})
	if err != nil {
		t.Fatalf("planService failed: %v", err)
	}
	assertContains(t, summary, "unsupported state")

	disabled := false
	cases := []struct {
		state string
		want  string
	}{
		{state: "", want: "disable cron at boot"},
		{state: "started", want: "ensure cron is started"},
		{state: "stopped", want: "ensure cron is stopped"},
		{state: "reloaded", want: "reload or restart cron"},
	}
	for _, tc := range cases {
		summary, _, err = planService(insp, &profile.ServiceSpec{Name: "cron", Enabled: &disabled, State: tc.state})
		if err != nil {
			t.Fatalf("planService(%q) failed: %v", tc.state, err)
		}
		assertContains(t, summary, tc.want)
	}

	summary, _, err = planService(insp, &profile.ServiceSpec{Name: "cron"})
	if err != nil {
		t.Fatalf("planService no-op failed: %v", err)
	}
	assertContains(t, summary, "no-op")
}

func TestPlanFirewall(t *testing.T) {
	insp := newFakeInspector()

	summary, details, err := planFirewall(insp, &profile.FirewallSpec{Backend: "ufw"})
	if err != nil {
		t.Fatalf("unsupported backend should be non-fatal in plan: %v", err)
	}
	assertContains(t, summary, "unsupported backend")
	if len(details) != 1 {
		t.Fatalf("expected one detail line for unsupported backend, got %d", len(details))
	}

	_, _, err = planFirewall(insp, &profile.FirewallSpec{Backend: "nftables"})
	if err == nil || !strings.Contains(err.Error(), "family is required") {
		t.Fatalf("expected missing family error, got %v", err)
	}
	_, _, err = planFirewall(insp, &profile.FirewallSpec{Backend: "nftables", Family: "inet"})
	if err == nil || !strings.Contains(err.Error(), "table is required") {
		t.Fatalf("expected missing table error, got %v", err)
	}
	_, _, err = planFirewall(insp, &profile.FirewallSpec{Backend: "nftables", Family: "inet", Table: "filter"})
	if err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
		t.Fatalf("expected missing managed_dest error, got %v", err)
	}
	_, _, err = planFirewall(insp, &profile.FirewallSpec{
		Backend:     "nftables",
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
	})
	if err == nil || !strings.Contains(err.Error(), "policies are required") {
		t.Fatalf("expected missing policies error, got %v", err)
	}

	insp.firewallInclude = true
	insp.statMap["/etc/nftables.d/99-hardline-firewall.nft"] = fakeFileInfo{name: "99-hardline-firewall.nft", size: 64, mode: 0o644}
	summary, details, err = planFirewall(insp, &profile.FirewallSpec{
		Backend:     "nftables",
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []profile.FirewallPolicy{
			{Chain: "input", Policy: "drop"},
		},
		Rules: []profile.FirewallRule{
			{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
		},
	})
	if err != nil {
		t.Fatalf("planFirewall failed: %v", err)
	}
	assertContains(t, summary, "deterministic")
	assertContains(t, strings.Join(details, "\n"), "include \"/etc/nftables.d/*.nft\" is present")
}

func TestPlanFirewallTemplate(t *testing.T) {
	insp := newFakeInspector()

	summary, _, err := planFirewallTemplate(insp, &profile.FirewallTemplateSpec{Backend: "ufw"})
	if err != nil {
		t.Fatalf("unsupported backend should be non-fatal in plan: %v", err)
	}
	assertContains(t, summary, "unsupported backend")

	_, _, err = planFirewallTemplate(insp, &profile.FirewallTemplateSpec{Backend: "nftables"})
	if err == nil || !strings.Contains(err.Error(), "template_src is required") {
		t.Fatalf("expected missing template_src error, got %v", err)
	}
	_, _, err = planFirewallTemplate(insp, &profile.FirewallTemplateSpec{
		Backend:     "nftables",
		TemplateSrc: "templates/fw.tmpl",
	})
	if err == nil || !strings.Contains(err.Error(), "template_dest is required") {
		t.Fatalf("expected missing template_dest error, got %v", err)
	}

	insp.statMap["/etc/nftables.d/99-hardline-firewall.nft"] = fakeFileInfo{name: "99-hardline-firewall.nft", size: 99, mode: 0o644}
	summary, details, err := planFirewallTemplate(insp, &profile.FirewallTemplateSpec{
		Backend:      "nftables",
		TemplateSrc:  "templates/fw.tmpl",
		TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Allow:        []profile.FirewallTemplateRule{{Port: 22, Proto: "tcp"}},
	})
	if err != nil {
		t.Fatalf("planFirewallTemplate failed: %v", err)
	}
	assertContains(t, summary, "best-effort")
	assertContains(t, strings.Join(details, "\n"), "template source")
}

func TestPlanValidate(t *testing.T) {
	insp := newFakeInspector()
	insp.sshInclude = true
	insp.firewallInclude = false
	insp.sshTestErr = errors.New("sshd test failure")
	insp.firewallTestErr = nil

	summary, details, err := planValidate(insp, "sshd")
	if err != nil {
		t.Fatalf("planValidate sshd failed: %v", err)
	}
	assertContains(t, summary, "validate sshd")
	assertContains(t, strings.Join(details, "\n"), "reports errors")

	summary, details, err = planValidate(insp, "firewall")
	if err != nil {
		t.Fatalf("planValidate firewall failed: %v", err)
	}
	assertContains(t, summary, "validate firewall")
	assertContains(t, strings.Join(details, "\n"), "missing (apply will append it)")

	insp.sshInclude = false
	insp.sshTestErr = nil
	summary, details, err = planValidate(insp, "sshd")
	if err != nil {
		t.Fatalf("planValidate sshd second run failed: %v", err)
	}
	assertContains(t, summary, "validate sshd")
	assertContains(t, strings.Join(details, "\n"), "missing (apply will append it)")
	assertContains(t, strings.Join(details, "\n"), "passes sshd -t")

	insp.firewallInclude = true
	insp.firewallTestErr = errors.New("nft invalid")
	summary, details, err = planValidate(insp, "firewall")
	if err != nil {
		t.Fatalf("planValidate firewall second run failed: %v", err)
	}
	assertContains(t, strings.Join(details, "\n"), "is present")
	assertContains(t, strings.Join(details, "\n"), "nft -c reports errors")

	summary, details, err = planValidate(insp, "other")
	if err != nil {
		t.Fatalf("unsupported validate kind should not error: %v", err)
	}
	assertContains(t, summary, "unsupported kind")
	if len(details) != 1 {
		t.Fatalf("expected one detail for unsupported validate, got %d", len(details))
	}
}

func assertContains(t *testing.T, s, needle string) {
	t.Helper()
	if !strings.Contains(s, needle) {
		t.Fatalf("expected %q to contain %q", s, needle)
	}
}
