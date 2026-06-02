package rollback

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

// fakeBehavior scripts a plugin's rollback/conflict behavior for orchestration
// tests. Nil funcs default to no-ops, mirroring the required-but-trivial contract.
type fakeBehavior struct {
	rollback       func(pluginapi.Host, pluginapi.ObjectRecord) error
	detectConflict func(pluginapi.Host, pluginapi.ObjectRecord) []string
}

func installPlugins(t *testing.T, m map[string]fakeBehavior) {
	prev := lookupPlugin
	lookupPlugin = func(name string) (pluginapi.Plugin, bool) {
		b, ok := m[name]
		if !ok {
			return pluginapi.Plugin{}, false
		}
		rb := b.rollback
		if rb == nil {
			rb = func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil }
		}
		dc := b.detectConflict
		if dc == nil {
			dc = func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil }
		}
		return pluginapi.Plugin{Name: name, Rollback: rb, DetectConflict: dc}, true
	}
	t.Cleanup(func() { lookupPlugin = prev })
}

func TestRollbackCommand_TargetValidationAndLoadError(t *testing.T) {
	t.Run("missing state", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		loadProfileID = func(string) (string, error) { return "profile", nil }
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
			return nil, errors.New("read remote rollback state")
		}

		err := rollbackCommand(cli.Command{
			Profile: "starter-secure-ubuntu-24.04-lts",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "read remote rollback state") {
			t.Fatalf("expected read state error, got %v", err)
		}
	})

	t.Run("load profile ID error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		loadProfileID = func(string) (string, error) { return "", errors.New("no profile.json") }

		err := rollbackCommand(cli.Command{
			Profile: "/nonexistent",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
		})
		if err == nil || !strings.Contains(err.Error(), "load profile ID") {
			t.Fatalf("expected load profile ID error, got %v", err)
		}
	})
}

func TestRollbackCommand_Success(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	var rolled []pluginapi.ObjectRecord
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) error {
			rolled = append(rolled, obj)
			return nil
		}},
	})

	j := NewJournal("example.com", "profile", "profile-dir")
	j.Status = "success"
	j.Steps = []StepRecord{
		{
			ID:           "template-step",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}},
			},
		},
	}
	var seenCfg connection.Config
	newSSHClient = func(cfg connection.Config) (*remote.Client, error) {
		seenCfg = cfg
		return nil, nil
	}
	loadProfileID = func(string) (string, error) { return "profile", nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	err := rollbackCommand(cli.Command{
		Profile: "starter-secure-ubuntu-24.04-lts",
		Host:    "example.com",
		User:    "root",
		KeyPath: "/tmp/key",
		Debug:   true,
	})
	if err != nil {
		t.Fatalf("rollbackCommand failed: %v", err)
	}
	if seenCfg.Host != "example.com" || seenCfg.User != "root" || seenCfg.KeyPath != "/tmp/key" {
		t.Fatalf("unexpected ssh config: %+v", seenCfg)
	}
	if len(rolled) != 1 || rolled[0].Kind != pluginapi.ObjectFile {
		t.Fatalf("expected one file rollback, got %#v", rolled)
	}
}

func TestRollbackCommand_ErrorPaths(t *testing.T) {
	t.Run("journal status not success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "failed"

		loadProfileID = func(string) (string, error) { return "profile", nil }
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
		err := rollbackCommand(cli.Command{
			Profile: "starter-secure-ubuntu-24.04-lts",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "not marked successful") {
			t.Fatalf("expected status error, got %v", err)
		}
	})

	t.Run("connect failed", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		loadProfileID = func(string) (string, error) { return "profile", nil }
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, errors.New("dial") }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		err := rollbackCommand(cli.Command{
			Profile: "starter-secure-ubuntu-24.04-lts",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "connect failed") {
			t.Fatalf("expected connect failed error, got %v", err)
		}
	})

	t.Run("step rollback error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return errors.New("boom") }},
		})

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "success"
		j.Steps = []StepRecord{
			{
				ID:           "bad",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}},
				},
			},
		}
		loadProfileID = func(string) (string, error) { return "profile", nil }
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
		err := rollbackCommand(cli.Command{
			Profile: "starter-secure-ubuntu-24.04-lts",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "rollback step") {
			t.Fatalf("expected rollback step failure, got %v", err)
		}
	})

	t.Run("sudo preflight failed", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		loadProfileID = func(string) (string, error) { return "profile", nil }
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return errors.New("sudo denied") }
		err := rollbackCommand(cli.Command{
			Profile: "starter-secure-ubuntu-24.04-lts",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "sudo preflight failed") {
			t.Fatalf("expected sudo preflight error, got %v", err)
		}
	})
}

func TestRollbackSteps(t *testing.T) {
	t.Run("sudo preflight failed", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		ensureRollbackSudo = func(_ *remote.Client) error { return errors.New("sudo denied") }

		err := RollbackSteps(nil, nil)
		if err == nil || !strings.Contains(err.Error(), "sudo preflight failed") {
			t.Fatalf("expected sudo preflight failure, got %v", err)
		}
	})

	t.Run("step rollback failed", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return errors.New("boom") }},
		})

		err := RollbackSteps(nil, []StepRecord{
			{
				ID:           "bad",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}},
				},
			},
		})
		if err == nil || !strings.Contains(err.Error(), "rollback step") {
			t.Fatalf("expected rollback step failure, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }

		if err := RollbackSteps(nil, []StepRecord{{ID: "v", Type: "validate", RollbackMode: pluginapi.ModeNoop}}); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("service steps are deferred until files are restored", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }

		var order []string
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { order = append(order, "template"); return nil }},
			"service":  {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { order = append(order, "service"); return nil }},
		})

		err := RollbackSteps(nil, []StepRecord{
			{
				ID:           "template-step",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/nftables.d/99-hardline-itest.nft", Existed: false}},
				},
			},
			{
				ID:           "service-step",
				Type:         "service",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nftables", Known: true, Enabled: true, Active: true}},
				},
			},
		})
		if err != nil {
			t.Fatalf("RollbackSteps failed: %v", err)
		}
		if len(order) != 2 || order[0] != "template" || order[1] != "service" {
			t.Fatalf("expected files restored before services, got %#v", order)
		}
	})
}

func TestRollbackStepsStrict(t *testing.T) {
	t.Run("best-effort errors are fatal in strict mode", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{
			"packages": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return errors.New("boom") }},
		})

		err := executeRollbackSteps(nil, []StepRecord{
			{
				ID:           "pkg",
				Type:         "packages",
				RollbackMode: pluginapi.ModeBestEffort,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "x"}},
				},
			},
		}, false, true, false)
		if err == nil || !strings.Contains(err.Error(), "rollback step") {
			t.Fatalf("expected strict rollback failure, got %v", err)
		}
	})

	t.Run("strict success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		if err := executeRollbackSteps(nil, []StepRecord{{ID: "v", Type: "validate", RollbackMode: pluginapi.ModeNoop}}, false, true, false); err != nil {
			t.Fatalf("expected strict rollback success, got %v", err)
		}
	})
}

func TestRollbackStepModes(t *testing.T) {
	fileObj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}

	t.Run("best effort continues", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{
			"packages": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return errors.New("boom") }},
		})
		step := StepRecord{
			ID:           "pkg",
			Type:         "packages",
			RollbackMode: pluginapi.ModeBestEffort,
			Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{}}},
		}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected best-effort step to continue, got %v", err)
		}
	})

	t.Run("deterministic fails", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return errors.New("boom") }},
		})
		step := StepRecord{
			ID:           "file",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{fileObj},
		}
		if err := rollbackStepWithMode(nil, step, false); err == nil {
			t.Fatal("expected deterministic step error")
		}
	})

	t.Run("noop", func(t *testing.T) {
		step := StepRecord{ID: "v", Type: "validate", RollbackMode: pluginapi.ModeNoop}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected noop success, got %v", err)
		}
	})

	t.Run("after snapshots are ignored", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil }},
		})
		step := StepRecord{
			ID:           "tmpl",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectValidate, Message: "noop"}},
			After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: nil}},
		}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected rollback to use before snapshots only, got %v", err)
		}
	})

	t.Run("unregistered plugin", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, map[string]fakeBehavior{})
		step := StepRecord{
			ID:           "ghost",
			Type:         "ghost",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{fileObj},
		}
		if err := rollbackStepWithMode(nil, step, false); err == nil || !strings.Contains(err.Error(), "not registered") {
			t.Fatalf("expected unregistered plugin error, got %v", err)
		}
	})
}

func TestStepActuallyChanged(t *testing.T) {
	t.Run("no before or after is no-op", func(t *testing.T) {
		if stepActuallyChanged(StepRecord{ID: "v", RollbackMode: pluginapi.ModeNoop}) {
			t.Fatal("expected no change for empty before/after")
		}
	})

	t.Run("before without after is changed", func(t *testing.T) {
		step := StepRecord{
			Before: []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
		}
		if !stepActuallyChanged(step) {
			t.Fatal("expected change when Before set and After empty")
		}
	})

	t.Run("identical before and after is no-op", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{
			Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, Mode: "0644", ContentB64: "abc",
		}}
		step := StepRecord{Before: []pluginapi.ObjectRecord{obj}, After: []pluginapi.ObjectRecord{obj}}
		if stepActuallyChanged(step) {
			t.Fatal("expected no change for identical before/after")
		}
	})

	t.Run("different before and after is changed", func(t *testing.T) {
		before := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{
			Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, Mode: "0644", ContentB64: "old",
		}}
		after := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{
			Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, Mode: "0600", ContentB64: "new",
		}}
		step := StepRecord{Before: []pluginapi.ObjectRecord{before}, After: []pluginapi.ObjectRecord{after}}
		if !stepActuallyChanged(step) {
			t.Fatal("expected change for different before/after")
		}
	})
}

func TestDeltaOnlyRollback(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }

	var count int
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { count++; return nil }},
	})

	obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{
		Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false,
	}}
	steps := []StepRecord{
		{
			ID:           "changed",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{obj},
			After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "new"}}},
		},
		{
			ID:           "idempotent",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{obj},
			After:        []pluginapi.ObjectRecord{obj},
		},
	}

	if err := RollbackSteps(nil, steps); err != nil {
		t.Fatalf("RollbackSteps failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one rollback for the changed step, got %d", count)
	}
}

func TestServiceReloadTriggered(t *testing.T) {
	cfg := func(id string, changed bool) StepRecord {
		before := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/x", Existed: true, ContentB64: "old"}}
		after := before
		if changed {
			after = pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/x", Existed: true, ContentB64: "new"}}
		}
		return StepRecord{ID: id, Type: "template", Before: []pluginapi.ObjectRecord{before}, After: []pluginapi.ObjectRecord{after}}
	}
	svc := func(reload *pluginapi.ServiceReload) StepRecord {
		return StepRecord{ID: "svc", Type: "service", Reload: reload}
	}

	cases := []struct {
		name string
		step StepRecord
		all  []StepRecord
		want bool
	}{
		{"nil reload", svc(nil), nil, false},
		{"non-reload action", svc(&pluginapi.ServiceReload{Action: "started"}), nil, false},
		{"on_change dep changed", svc(&pluginapi.ServiceReload{Action: "reloaded", RestartPolicy: "on_change", RestartDeps: []string{"cfg"}}), []StepRecord{cfg("cfg", true)}, true},
		{"on_change dep unchanged", svc(&pluginapi.ServiceReload{Action: "reloaded", RestartPolicy: "on_change", RestartDeps: []string{"cfg"}}), []StepRecord{cfg("cfg", false)}, false},
		{"on_change dep missing", svc(&pluginapi.ServiceReload{Action: "restarted", RestartPolicy: "on_change", RestartDeps: []string{"ghost"}}), []StepRecord{cfg("cfg", true)}, false},
		{"always policy", svc(&pluginapi.ServiceReload{Action: "restarted", RestartPolicy: "always"}), nil, true},
		{"absent policy", svc(&pluginapi.ServiceReload{Action: "restarted"}), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serviceReloadTriggered(tc.step, tc.all); got != tc.want {
				t.Fatalf("serviceReloadTriggered = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServiceReloadRollbackSkipGate(t *testing.T) {
	cfgChanged := StepRecord{
		ID: "cfg", Type: "template", RollbackMode: pluginapi.ModeDeterministic,
		Before: []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
		After:  []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "new"}}},
	}
	svcObj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "ssh", Enabled: true, Active: true, Known: true}}
	svcStep := func(deps []string) StepRecord {
		return StepRecord{
			ID: "svc", Type: "service", RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{svcObj},
			After:  []pluginapi.ObjectRecord{svcObj},
			Reload: &pluginapi.ServiceReload{Action: "reloaded", RestartPolicy: "on_change", RestartDeps: deps},
		}
	}

	run := func(t *testing.T, deps []string) int {
		restore := stubRollbackHooks()
		defer restore()
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		var svcRollbacks int
		installPlugins(t, map[string]fakeBehavior{
			"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil }},
			"service":  {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { svcRollbacks++; return nil }},
		})
		if err := RollbackSteps(nil, []StepRecord{cfgChanged, svcStep(deps)}); err != nil {
			t.Fatalf("RollbackSteps failed: %v", err)
		}
		return svcRollbacks
	}

	t.Run("reloads when its config dep changed", func(t *testing.T) {
		if got := run(t, []string{"cfg"}); got != 1 {
			t.Fatalf("expected the no-delta service step to roll back once, got %d", got)
		}
	})
	t.Run("stays skipped when dep is unrelated", func(t *testing.T) {
		if got := run(t, []string{"other"}); got != 0 {
			t.Fatalf("expected the no-delta service step to be skipped, got %d", got)
		}
	})
}

func TestExecuteRollbackSteps_Conflicts(t *testing.T) {
	step := StepRecord{
		ID:           "s",
		Type:         "template",
		RollbackMode: pluginapi.ModeDeterministic,
		Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
		After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "x"}}},
	}
	conflicting := map[string]fakeBehavior{
		"template": {detectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return []string{"drifted since apply"} }},
	}

	t.Run("blocks without force", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, conflicting)
		err := executeRollbackSteps(nil, []StepRecord{step}, false, false, false)
		if err == nil || !strings.Contains(err.Error(), "force-rollback") {
			t.Fatalf("expected force-rollback error, got %v", err)
		}
	})

	t.Run("proceeds with force", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, conflicting)
		if err := executeRollbackSteps(nil, []StepRecord{step}, false, false, true); err != nil {
			t.Fatalf("expected force rollback to succeed, got %v", err)
		}
	})
}

func TestCheckStepConflictsUnregistered(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()
	installPlugins(t, map[string]fakeBehavior{})

	step := StepRecord{Type: "ghost", After: []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{}}}}
	if got := checkStepConflicts(nil, step); got != nil {
		t.Fatalf("expected nil for unregistered plugin, got %v", got)
	}
}

func TestRollbackWrapperExitHook(t *testing.T) {
	t.Run("error exits non-zero", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		runRollbackCommand = func(cli.Command) error { return errors.New("boom") }
		exitCode := -1
		exitProcess = func(code int) { exitCode = code }

		Rollback(cli.Command{})
		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}
	})

	t.Run("success does not exit", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		runRollbackCommand = func(cli.Command) error { return nil }
		called := false
		exitProcess = func(int) { called = true }

		Rollback(cli.Command{})
		if called {
			t.Fatal("expected no exit on success")
		}
	})
}

func TestFormatRollbackDuration(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0ms"},
		{250 * time.Millisecond, "250ms"},
		{1500 * time.Millisecond, "1.5s"},
		{90 * time.Second, "1m30s"},
	}
	for _, tc := range cases {
		if got := formatRollbackDuration(tc.d); got != tc.want {
			t.Fatalf("formatRollbackDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func stubRollbackHooks() func() {
	prevNewSSH := newSSHClient
	prevEnsureSudo := ensureRollbackSudo
	prevLoadRemoteJournal := loadRemoteJournal
	prevDeleteJournal := deleteJournal
	prevLoadProfileID := loadProfileID
	prevRunRollbackCommand := runRollbackCommand
	prevExit := exitProcess

	return func() {
		newSSHClient = prevNewSSH
		ensureRollbackSudo = prevEnsureSudo
		loadRemoteJournal = prevLoadRemoteJournal
		deleteJournal = prevDeleteJournal
		loadProfileID = prevLoadProfileID
		runRollbackCommand = prevRunRollbackCommand
		exitProcess = prevExit
	}
}
