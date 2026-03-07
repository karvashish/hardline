package apply

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestServiceDirtyHelpers(t *testing.T) {
	resetApplyStepState()
	if got := normalizeServiceUnit("  ssh  "); got != "ssh" {
		t.Fatalf("unexpected normalized service unit: %q", got)
	}

	markServiceDirty("  ssh  ")
	if !isServiceDirty("ssh") {
		t.Fatal("expected ssh to be dirty")
	}
	clearServiceDirty("ssh")
	if isServiceDirty("ssh") {
		t.Fatal("expected ssh to be clean")
	}

	markServiceDirty(" ")
	if isServiceDirty("") {
		t.Fatal("expected empty service key to remain clean")
	}
}

func TestHandleStepAndValidateDispatch(t *testing.T) {
	prev := applyActionRegistry
	defer func() {
		applyActionRegistry = prev
	}()

	applyActionRegistry = pluginapi.NewApplyRegistry()

	calledApply := false
	calledValidate := false
	err := RegisterApplyAction(pluginapi.ApplyHandler{
		Type: "fake",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			calledApply = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected apply context profile: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step passed to apply: %+v", s)
			}
			return nil
		},
		ValidateKinds: map[string]func(pluginapi.ApplyContext) error{
			"vk": func(ctx pluginapi.ApplyContext) error {
				calledValidate = true
				if ctx.Profile == nil || ctx.Profile.ID != "p1" {
					t.Fatalf("unexpected validate context profile: %+v", ctx.Profile)
				}
				return nil
			},
		},
	})
	if err != nil {
		t.Fatalf("register apply handler failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}

	if err := handleStep(nil, p, profile.Step{ID: "v0", Type: "validate"}); err == nil || !strings.Contains(err.Error(), "validate spec missing") {
		t.Fatalf("expected validate spec missing error, got %v", err)
	}

	if err := handleStep(nil, p, profile.Step{ID: "v1", Type: "validate", Validate: "vk"}); err != nil {
		t.Fatalf("validate handleStep failed: %v", err)
	}
	if !calledValidate {
		t.Fatal("expected validate hook to be called")
	}

	if err := applyValidateByKind(nil, p, "missing-kind"); err == nil || !strings.Contains(err.Error(), "unsupported validate kind") {
		t.Fatalf("expected unsupported validate kind error, got %v", err)
	}

	if err := handleStep(nil, p, profile.Step{ID: "u", Type: "unknown"}); err != nil {
		t.Fatalf("unknown step should be noop, got %v", err)
	}

	if err := handleStep(nil, p, profile.Step{ID: "s1", Type: "fake"}); err != nil {
		t.Fatalf("fake apply handler failed: %v", err)
	}
	if !calledApply {
		t.Fatal("expected fake apply handler to be called")
	}
}

func TestRegistryContextHelpers(t *testing.T) {
	p := &profile.Profile{ID: "p2"}
	actx := applyActionContext(nil, p)
	if actx.Profile != p || actx.Client != nil {
		t.Fatalf("unexpected apply action context: %+v", actx)
	}

	rctx := applyRollbackContext(nil, p)
	if rctx.Profile != p || rctx.Client != nil {
		t.Fatalf("unexpected rollback context: %+v", rctx)
	}
}

func TestRegisterRollbackAction(t *testing.T) {
	prev := applyRollbackRegistry
	defer func() {
		applyRollbackRegistry = prev
	}()

	applyRollbackRegistry = pluginapi.NewRollbackRegistry()
	called := false
	err := RegisterRollbackAction(pluginapi.RollbackHandler{
		Type: "rb",
		Capture: func(pluginapi.RollbackContext, profile.Step) (rollback.StepRecord, error) {
			called = true
			return rollback.StepRecord{ID: "rb", Type: "rb", RollbackMode: rollback.ModeNoop}, nil
		},
	})
	if err != nil {
		t.Fatalf("register rollback handler failed: %v", err)
	}

	h, ok := applyRollbackRegistry.LookupType("rb")
	if !ok {
		t.Fatal("expected rollback handler lookup to succeed")
	}
	if _, err := h.Capture(pluginapi.RollbackContext{}, profile.Step{ID: "x", Type: "rb"}); err != nil {
		t.Fatalf("rollback capture failed: %v", err)
	}
	if !called {
		t.Fatal("expected rollback capture to be called")
	}
}

func TestNewDefaultRegistries(t *testing.T) {
	prevRunRoot := runRootCmd
	prevRunRootOut := runRootCmdWithOutput
	prevReadRoot := readRootFile
	prevSFTP := newSFTPClient
	prevWrite := writeRootFile
	defer func() {
		runRootCmd = prevRunRoot
		runRootCmdWithOutput = prevRunRootOut
		readRootFile = prevReadRoot
		newSFTPClient = prevSFTP
		writeRootFile = prevWrite
	}()

	runRootCalls := 0
	runRootOutCalls := 0
	readRootCalls := 0

	runRootCmd = func(_ *ssh.Client, _ string) error {
		runRootCalls++
		return nil
	}
	runRootCmdWithOutput = func(_ *ssh.Client, _ string) (string, error) {
		runRootOutCalls++
		return "enabled\n", nil
	}
	readRootFile = func(_ *ssh.Client, _ string) (string, error) {
		readRootCalls++
		return "content", nil
	}
	newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
	writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }

	ar := newDefaultApplyRegistry()

	applyCases := []profile.Step{
		{ID: "p", Type: "packages", Packages: &profile.PackageSpec{Update: true}},
		{ID: "t", Type: "template", Template: &profile.TemplateSpec{Src: "x", Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}},
		{ID: "s", Type: "service", Service: &profile.ServiceSpec{Name: "ssh", State: "started"}},
		{ID: "f", Type: "firewall", Firewall: &profile.FirewallSpec{Backend: "ufw"}},
		{ID: "ft", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{Backend: "ufw"}},
	}

	for _, step := range applyCases {
		h, ok := ar.LookupType(step.Type)
		if !ok {
			t.Fatalf("missing apply handler for %q", step.Type)
		}
		_ = h.Apply(pluginapi.ApplyContext{}, step)
	}

	if fn, ok := ar.LookupValidate("sshd"); ok {
		_ = fn(pluginapi.ApplyContext{})
	}
	if fn, ok := ar.LookupValidate("firewall"); ok {
		_ = fn(pluginapi.ApplyContext{})
	}

	rr := newDefaultRollbackRegistry()

	validate, ok := rr.LookupType("validate")
	if !ok {
		t.Fatal("missing validate rollback handler")
	}
	rec, err := validate.Capture(pluginapi.RollbackContext{}, profile.Step{ID: "v", Type: "validate"})
	if err != nil {
		t.Fatalf("validate rollback capture failed: %v", err)
	}
	if rec.RollbackMode != rollback.ModeNoop {
		t.Fatalf("unexpected validate rollback mode: %q", rec.RollbackMode)
	}

	rollbackCases := []profile.Step{
		{ID: "p", Type: "packages", Packages: &profile.PackageSpec{Install: []string{"curl"}}},
		{ID: "t", Type: "template", Template: &profile.TemplateSpec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}},
		{ID: "s", Type: "service", Service: &profile.ServiceSpec{Name: "ssh"}},
		{ID: "f", Type: "firewall", Firewall: &profile.FirewallSpec{ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft"}},
		{ID: "ft", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"}},
	}

	for _, step := range rollbackCases {
		h, ok := rr.LookupType(step.Type)
		if !ok {
			t.Fatalf("missing rollback handler for %q", step.Type)
		}
		if _, err := h.Capture(pluginapi.RollbackContext{}, step); err != nil {
			t.Fatalf("rollback capture failed for %q: %v", step.Type, err)
		}
	}

	if runRootCalls == 0 || runRootOutCalls == 0 || readRootCalls == 0 {
		t.Fatalf("expected default registry closures to use all deps (runRoot=%d runRootOut=%d readRoot=%d)", runRootCalls, runRootOutCalls, readRootCalls)
	}
}

func TestNewDefaultRegistries_RegisterPanics(t *testing.T) {
	prevRunRoot := runRootCmd
	defer func() {
		runRootCmd = prevRunRoot
	}()
	runRootCmd = func(_ *ssh.Client, _ string) error { return errors.New("x") }

	_ = newDefaultApplyRegistry()
	_ = newDefaultRollbackRegistry()
}
