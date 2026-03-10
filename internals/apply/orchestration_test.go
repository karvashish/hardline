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
}

func TestHandleStepDispatch(t *testing.T) {
	prev := pluginRegistry
	defer func() { pluginRegistry = prev }()

	pluginRegistry = pluginapi.NewRegistry()

	called := false
	err := RegisterPlugin(pluginapi.Plugin{
		Name:               "fake",
		InternalValidation: true,
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			called = true
			if ctx.Profile == nil || ctx.Profile.ID != "p1" {
				t.Fatalf("unexpected apply context profile: %+v", ctx.Profile)
			}
			if s.ID != "s1" {
				t.Fatalf("unexpected step passed to apply: %+v", s)
			}
			return nil
		},
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	})
	if err != nil {
		t.Fatalf("register plugin failed: %v", err)
	}

	p := &profile.Profile{ID: "p1"}
	if err := handleStep(nil, p, profile.Step{ID: "u", Plugin: "unknown"}); err != nil {
		t.Fatalf("unknown plugin should be noop, got %v", err)
	}

	if err := handleStep(nil, p, profile.Step{ID: "s1", Plugin: "fake"}); err != nil {
		t.Fatalf("fake plugin apply failed: %v", err)
	}
	if !called {
		t.Fatal("expected fake plugin to be called")
	}
}

func TestHandleStep_ValidationPolicy(t *testing.T) {
	prev := pluginRegistry
	defer func() { pluginRegistry = prev }()

	pluginRegistry = pluginapi.NewRegistry()
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

	err = handleStep(nil, &profile.Profile{}, profile.Step{ID: "x", Plugin: "external"})
	if err == nil || !strings.Contains(err.Error(), "allow_unvalidated=true") {
		t.Fatalf("expected validation policy error, got %v", err)
	}

	err = handleStep(nil, &profile.Profile{}, profile.Step{
		ID:               "x",
		Plugin:           "external",
		AllowUnvalidated: true,
	})
	if err != nil {
		t.Fatalf("expected allow_unvalidated to permit external plugin, got %v", err)
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
	runRootCmd = func(*ssh.Client, string) error {
		runRootCalls++
		return nil
	}
	runRootCmdWithOutput = func(*ssh.Client, string) (string, error) { return "", nil }
	readRootFile = func(*ssh.Client, string) (string, error) { return "", nil }
	newSFTPClient = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	writeRootFile = func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil }

	reg := newDefaultPluginRegistry()
	for _, name := range []string{"packages", "template", "service", "firewall", "firewall_template"} {
		plugin, ok := reg.Lookup(name)
		if !ok {
			t.Fatalf("missing builtin plugin %q", name)
		}
		if !plugin.InternalValidation {
			t.Fatalf("expected builtin plugin %q to validate internally", name)
		}
	}

	packagesPlugin, _ := reg.Lookup("packages")
	if err := packagesPlugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "p1",
		Plugin: "packages",
		Config: map[string]any{"update": true},
	}); err != nil {
		t.Fatalf("packages apply failed: %v", err)
	}

	if runRootCalls == 0 {
		t.Fatal("expected builtin registry to capture runtime dependencies")
	}
}

func TestNewDefaultRegistries_RegisterPanics(t *testing.T) {
	prevRunRoot := runRootCmd
	defer func() {
		runRootCmd = prevRunRoot
	}()
	runRootCmd = func(*ssh.Client, string) error { return errors.New("x") }

	_ = newDefaultPluginRegistry()
}

func TestRegisterPluginBundle(t *testing.T) {
	prev := pluginRegistry
	defer func() { pluginRegistry = prev }()

	pluginRegistry = pluginapi.NewRegistry()
	err := RegisterPluginBundle(pluginapi.PluginBundle{
		Name: "bundle",
		Plugins: []pluginapi.Plugin{{
			Name:               "rb",
			InternalValidation: true,
			Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
			Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, nil
			},
			Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
				return rollback.StepRecord{ID: "rb", Type: "rb", RollbackMode: rollback.ModeNoop}, nil
			},
		}},
	})
	if err != nil {
		t.Fatalf("register bundle failed: %v", err)
	}

	plugin, ok := pluginRegistry.Lookup("rb")
	if !ok {
		t.Fatal("expected plugin lookup to succeed")
	}
	if _, err := plugin.Rollback(pluginapi.RollbackContext{}, profile.Step{ID: "x", Plugin: "rb"}); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}
