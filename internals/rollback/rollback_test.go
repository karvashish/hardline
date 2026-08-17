package rollback

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

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
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
			return nil, errors.New("read remote rollback state")
		}

		err := rollbackWithBundle(cli.Command{
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

	t.Run("missing verified bundle", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		err := rollbackCommand(cli.Command{
			Profile: "/nonexistent",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "verified profile bundle") {
			t.Fatalf("expected missing bundle error, got %v", err)
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
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	err := rollbackWithBundle(cli.Command{
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
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
		err := rollbackWithBundle(cli.Command{
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
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, errors.New("dial") }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		err := rollbackWithBundle(cli.Command{
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
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return nil }
		loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
		err := rollbackWithBundle(cli.Command{
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
		newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
		ensureRollbackSudo = func(_ *remote.Client) error { return errors.New("sudo denied") }
		err := rollbackWithBundle(cli.Command{
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

		_, err := executeRollbackSteps(nil, []StepRecord{
			{
				ID:           "pkg",
				Type:         "packages",
				RollbackMode: pluginapi.ModeBestEffort,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "x"}},
				},
			},
		}, false, true)
		if err == nil || !strings.Contains(err.Error(), "rollback step") {
			t.Fatalf("expected strict rollback failure, got %v", err)
		}
	})

	t.Run("strict success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		if _, err := executeRollbackSteps(nil, []StepRecord{{ID: "v", Type: "validate", RollbackMode: pluginapi.ModeNoop}}, false, true); err != nil {
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
		if _, err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected best-effort step to continue, got %v", err)
		}
	})

	t.Run("irreversible continues and reports the object as degraded", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		reverted := 0
		installPlugins(t, map[string]fakeBehavior{
			"packages": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
				reverted++
				return errors.New("the purged package is no longer in any repo")
			}},
		})
		step := StepRecord{
			ID:           "pkg",
			Type:         "packages",
			RollbackMode: pluginapi.ModeIrreversible,
			Before: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "a"}},
				{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "b"}},
			},
		}
		degraded, err := rollbackStepWithMode(nil, step, false)
		if err != nil {
			t.Fatalf("a step hardline never claimed it could revert must not abort the run, got %v", err)
		}
		if reverted != 2 {
			t.Fatalf("expected every object to be attempted, got %d", reverted)
		}
		if len(degraded) != 2 {
			t.Fatalf("expected both failures reported as degraded, got %v", degraded)
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
		if _, err := rollbackStepWithMode(nil, step, false); err == nil {
			t.Fatal("expected deterministic step error")
		}
	})

	t.Run("noop", func(t *testing.T) {
		step := StepRecord{ID: "v", Type: "validate", RollbackMode: pluginapi.ModeNoop}
		if _, err := rollbackStepWithMode(nil, step, false); err != nil {
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
			Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, Message: "noop"}},
			After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: nil}},
		}
		if _, err := rollbackStepWithMode(nil, step, false); err != nil {
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
		if _, err := rollbackStepWithMode(nil, step, false); err == nil || !strings.Contains(err.Error(), "not registered") {
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
		err := preflightRollbackConflicts(nil, []StepRecord{step}, false, false)
		if err == nil || !strings.Contains(err.Error(), "force-rollback") {
			t.Fatalf("expected force-rollback error, got %v", err)
		}
	})

	t.Run("proceeds with force", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		installPlugins(t, conflicting)
		if err := preflightRollbackConflicts(nil, []StepRecord{step}, true, false); err != nil {
			t.Fatalf("expected force rollback to succeed, got %v", err)
		}
	})
}

func TestPreflightLetsAResumeFinishAnAlreadyRevertedStep(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	reverted := StepRecord{
		ID:           "reverted",
		Type:         "template",
		RollbackMode: pluginapi.ModeDeterministic,
		Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
		After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "x"}}},
	}
	installPlugins(t, map[string]fakeBehavior{
		"template": {detectConflict: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) []string {
			if obj.File.Existed {
				return []string{"the file this profile wrote is gone"}
			}
			return nil
		}},
	})

	if err := preflightRollbackConflicts(nil, []StepRecord{reverted}, false, true); err != nil {
		t.Fatalf("a resume must not refuse a step an earlier attempt already reverted, got %v", err)
	}
	if err := preflightRollbackConflicts(nil, []StepRecord{reverted}, false, false); err == nil {
		t.Fatal("a fresh rollback must still report the drift")
	}
}

func TestPreflightStillRefusesRealDriftOnAResume(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	step := StepRecord{
		ID:           "edited",
		Type:         "template",
		RollbackMode: pluginapi.ModeDeterministic,
		Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
		After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "x"}}},
	}
	installPlugins(t, map[string]fakeBehavior{
		"template": {detectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return []string{"edited by hand"} }},
	})

	err := preflightRollbackConflicts(nil, []StepRecord{step}, false, true)
	if err == nil || !strings.Contains(err.Error(), "force-rollback") {
		t.Fatalf("a step matching neither capture must still be refused on a resume, got %v", err)
	}

	step.Before = nil
	err = preflightRollbackConflicts(nil, []StepRecord{step}, false, true)
	if err == nil || !strings.Contains(err.Error(), "force-rollback") {
		t.Fatalf("a step with nothing to compare against cannot be assumed reverted, got %v", err)
	}
}

func TestCheckStepConflictsUnregistered(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()
	installPlugins(t, map[string]fakeBehavior{})

	step := StepRecord{Type: "ghost", After: []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{}}}}
	if got := checkStepConflicts(nil, step, false); got != nil {
		t.Fatalf("expected nil for unregistered plugin, got %v", got)
	}
}

func TestRollbackWrapperExitHook(t *testing.T) {
	t.Run("error exits non-zero", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		runRollbackCommand = func(cli.Command, *verify.VerifiedBundle) error { return errors.New("boom") }
		exitCode := -1
		exitProcess = func(code int) { exitCode = code }

		rollbackWithBundleTop(cli.Command{})
		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}
	})

	t.Run("success does not exit", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		runRollbackCommand = func(cli.Command, *verify.VerifiedBundle) error { return nil }
		called := false
		exitProcess = func(int) { called = true }

		rollbackWithBundleTop(cli.Command{})
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
	prevLoadLocalJournal := loadLocalJournal
	prevSaveLocalJournal := saveLocalJournal
	prevRemoveLocalJournal := removeLocalJournal
	prevSaveRemoteJournal := saveRemoteJournal
	prevAcquireLock := acquireMutationLock
	prevReleaseLock := releaseMutationLock

	prevRunRollbackCommand := runRollbackCommand
	prevExit := exitProcess

	acquireMutationLock = func(*remote.Client) error { return nil }
	releaseMutationLock = func(*remote.Client) error { return nil }
	saveRemoteJournal = func(*remote.Client, *Journal) error { return nil }
	saveLocalJournal = func(*Journal) error { return nil }

	return func() {
		newSSHClient = prevNewSSH
		ensureRollbackSudo = prevEnsureSudo
		loadRemoteJournal = prevLoadRemoteJournal
		deleteJournal = prevDeleteJournal
		loadLocalJournal = prevLoadLocalJournal
		saveLocalJournal = prevSaveLocalJournal
		removeLocalJournal = prevRemoveLocalJournal
		saveRemoteJournal = prevSaveRemoteJournal
		acquireMutationLock = prevAcquireLock
		releaseMutationLock = prevReleaseLock

		runRollbackCommand = prevRunRollbackCommand
		exitProcess = prevExit
		rollbackBundleProfile = &profile.Profile{ID: "profile"}
	}
}

var rollbackBundleProfile = &profile.Profile{ID: "profile"}

func rollbackBundle() *verify.VerifiedBundle {
	if rollbackBundleProfile == nil {
		return nil
	}
	return &verify.VerifiedBundle{Profile: rollbackBundleProfile}
}

func rollbackWithBundle(c cli.Command) error {
	return rollbackCommand(c, rollbackBundle())
}

func rollbackWithBundleTop(c cli.Command) {
	Rollback(c, rollbackBundle())
}

func TestRollbackCommand_TakesMutationLock(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{"template": {}})

	acquired := false
	released := false
	acquireMutationLock = func(*remote.Client) error {
		acquired = true
		return nil
	}
	releaseMutationLock = func(*remote.Client) error {
		released = true
		return nil
	}

	j := successJournal()
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return j, nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	if err := rollbackWithBundle(baseRollbackCommand()); err != nil {
		t.Fatalf("rollbackCommand failed: %v", err)
	}
	if !acquired || !released {
		t.Fatalf("expected the mutation lock to be taken and released, acquired=%v released=%v", acquired, released)
	}
}

func TestRollbackCommand_LockContentionAborts(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	loaded := false
	acquireMutationLock = func(*remote.Client) error { return errors.New("lock held") }
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
		loaded = true
		return successJournal(), nil
	}

	err := rollbackWithBundle(baseRollbackCommand())
	if err == nil || !strings.Contains(err.Error(), "lock held") {
		t.Fatalf("expected lock contention error, got %v", err)
	}
	if loaded {
		t.Fatal("expected rollback to abort before reading the journal")
	}
}

func TestPreflightRollbackConflicts_ChecksEverythingFirst(t *testing.T) {
	var reverted []string
	installPlugins(t, map[string]fakeBehavior{
		"template": {
			rollback: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) error {
				reverted = append(reverted, obj.File.Path)
				return nil
			},
			detectConflict: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) []string {
				if obj.File != nil && obj.File.Path == "/etc/first.conf" {
					return []string{"/etc/first.conf: changed since apply"}
				}
				return nil
			},
		},
	})

	steps := []StepRecord{
		changedFileStep("first", "/etc/first.conf"),
		changedFileStep("second", "/etc/second.conf"),
	}

	err := preflightRollbackConflicts(nil, steps, false, false)
	if err == nil || !strings.Contains(err.Error(), "--force-rollback") {
		t.Fatalf("expected a conflict error, got %v", err)
	}
	if len(reverted) != 0 {
		t.Fatalf("expected no step to be reverted before the conflict was reported, got %+v", reverted)
	}
}

func TestPreflightRollbackConflicts_ForceReportsEveryConflict(t *testing.T) {
	installPlugins(t, map[string]fakeBehavior{
		"template": {
			detectConflict: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) []string {
				return []string{obj.File.Path + ": changed since apply"}
			},
		},
	})

	steps := []StepRecord{
		changedFileStep("first", "/etc/first.conf"),
		changedFileStep("second", "/etc/second.conf"),
	}

	err := preflightRollbackConflicts(nil, steps, false, false)
	if err == nil {
		t.Fatal("expected a conflict error")
	}
	for _, want := range []string{"/etc/first.conf", "/etc/second.conf"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected every conflict reported, %q missing from %v", want, err)
		}
	}

	if err := preflightRollbackConflicts(nil, steps, true, false); err != nil {
		t.Fatalf("expected --force-rollback to proceed, got %v", err)
	}
}

func TestExecuteRollbackSteps_ReportsDegradedRestoration(t *testing.T) {
	installPlugins(t, map[string]fakeBehavior{
		"packages": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
			return errors.New("package no longer available")
		}},
	})

	step := changedFileStep("pkg", "/etc/pkg.conf")
	step.Type = "packages"
	step.RollbackMode = pluginapi.ModeBestEffort

	degraded, err := executeRollbackSteps(nil, []StepRecord{step}, false, false)
	if err != nil {
		t.Fatalf("expected best-effort failure to be absorbed, got %v", err)
	}
	if len(degraded) != 1 || !strings.Contains(degraded[0], "package no longer available") {
		t.Fatalf("expected a degraded note, got %+v", degraded)
	}

	prevSudo := ensureRollbackSudo
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	defer func() { ensureRollbackSudo = prevSudo }()
	if err := RollbackSteps(nil, []StepRecord{step}); err == nil ||
		!strings.Contains(err.Error(), "degraded restoration") {
		t.Fatalf("expected RollbackSteps to report degraded restoration, got %v", err)
	}
}

func TestRollbackCommand_LocalJournalRecovery(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{"template": {}})

	removed := false
	remoteRead := false
	loadLocalJournal = func(host, profileID string) (*Journal, error) { return successJournal(), nil }
	removeLocalJournal = func(*Journal) error {
		removed = true
		return nil
	}
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
		remoteRead = true
		return nil, errors.New("no journal on target")
	}
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }

	c := baseRollbackCommand()
	c.LocalJournal = true
	if err := rollbackWithBundle(c); err != nil {
		t.Fatalf("local-journal rollback failed: %v", err)
	}
	if remoteRead {
		t.Fatal("expected --local-journal to skip the target journal entirely")
	}
	if !removed {
		t.Fatal("expected the consumed runner-side journal to be deleted")
	}
}

func TestRollbackCommand_LocalJournalRejectsForeignHost(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{"template": {}})

	loadLocalJournal = func(host, profileID string) (*Journal, error) {
		j := successJournal()
		j.Host = "other.example.com"
		return j, nil
	}
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }

	c := baseRollbackCommand()
	c.LocalJournal = true
	err := rollbackWithBundle(c)
	if err == nil || !strings.Contains(err.Error(), "written for host") {
		t.Fatalf("expected a host mismatch error, got %v", err)
	}
}

func TestConsumeJournal_DeleteFailureIsFatal(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	deleteJournal = func(_ *remote.Client, _, _ string) error { return errors.New("read-only fs") }
	err := consumeJournal(nil, baseRollbackCommand(), successJournal())
	if err == nil || !strings.Contains(err.Error(), "delete remote journal") {
		t.Fatalf("expected journal deletion failure to be fatal, got %v", err)
	}
}

func baseRollbackCommand() cli.Command {
	return cli.Command{
		Profile: "starter-secure-ubuntu-24.04-lts",
		Host:    "example.com",
		User:    "root",
		KeyPath: "/tmp/key",
		Debug:   true,
	}
}

func successJournal() *Journal {
	j := NewJournal("example.com", "profile", "profile-dir")
	j.Status = "success"
	j.Steps = []StepRecord{changedFileStep("template-step", "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")}
	return j
}

func changedFileStep(id, path string) StepRecord {
	return StepRecord{
		ID:           id,
		Type:         "template",
		RollbackMode: pluginapi.ModeDeterministic,
		Before: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: path, Existed: false}},
		},
		After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: path, Existed: true, ContentB64: "eA=="}},
		},
	}
}

func TestPreflightRejectsUnregisteredPlugin(t *testing.T) {
	var reverted []string
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(_ pluginapi.Host, obj pluginapi.ObjectRecord) error {
			reverted = append(reverted, obj.File.Path)
			return nil
		}},
	})

	gone := changedFileStep("gone", "/etc/gone.conf")
	gone.Type = "retired_plugin"

	steps := []StepRecord{gone, changedFileStep("known", "/etc/known.conf")}

	err := preflightRollbackConflicts(nil, steps, false, false)
	if err == nil || !strings.Contains(err.Error(), "is not registered") {
		t.Fatalf("expected an unregistered-plugin refusal, got %v", err)
	}
	if len(reverted) != 0 {
		t.Fatalf("expected nothing to be reverted, got %+v", reverted)
	}

	if err := preflightRollbackConflicts(nil, steps, true, false); err == nil {
		t.Fatal("expected --force-rollback not to bypass a missing plugin")
	}
}

func TestClaimJournalBeforeRevert(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	var order []string
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
			order = append(order, "revert")
			return nil
		}},
	})

	var claimedStatus string
	saveRemoteJournal = func(_ *remote.Client, j *Journal) error {
		order = append(order, "claim")
		claimedStatus = j.Status
		return nil
	}
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return successJournal(), nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	if err := rollbackWithBundle(baseRollbackCommand()); err != nil {
		t.Fatalf("rollbackCommand failed: %v", err)
	}
	if len(order) < 2 || order[0] != "claim" {
		t.Fatalf("expected the journal to be claimed before the first revert, got %v", order)
	}
	if claimedStatus != "rolling_back" {
		t.Fatalf("expected the claim to mark the journal rolling_back, got %q", claimedStatus)
	}
}

func TestConflictRefusalLeavesJournalRerunnable(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{
		"template": {
			rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
			detectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string {
				return []string{"/etc/x.conf: changed since apply"}
			},
		},
	})

	claimed := false
	saveRemoteJournal = func(_ *remote.Client, _ *Journal) error {
		claimed = true
		return nil
	}
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return successJournal(), nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	err := rollbackWithBundle(baseRollbackCommand())
	if err == nil || !strings.Contains(err.Error(), "--force-rollback") {
		t.Fatalf("expected the drift refusal, got %v", err)
	}
	if claimed {
		t.Fatal("a refused rollback must not claim the journal: the --force-rollback retry it recommends would then be rejected as not successful")
	}
}

func TestFailedRollbackLeavesTheJournalResumable(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
			return errors.New("host went away")
		}},
	})

	deleted := false
	saveRemoteJournal = func(*remote.Client, *Journal) error { return nil }
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return successJournal(), nil }
	deleteJournal = func(_ *remote.Client, _, _ string) error {
		deleted = true
		return nil
	}

	err := rollbackWithBundle(baseRollbackCommand())
	if err == nil || !strings.Contains(err.Error(), "host went away") {
		t.Fatalf("expected the step failure to surface, got %v", err)
	}
	if !strings.Contains(err.Error(), "running rollback again resumes it") {
		t.Fatalf("expected the operator to be told the run is still journalled, got %v", err)
	}
	if deleted {
		t.Fatal("a failed rollback must keep the journal so the retry has something to resume")
	}
}

func TestRollbackResumesAClaimedJournal(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	reverted := 0
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
			reverted++
			return nil
		}},
	})

	saveRemoteJournal = func(*remote.Client, *Journal) error { return nil }
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
		j := successJournal()
		j.Status = "rolling_back"
		return j, nil
	}
	deleteJournal = func(_ *remote.Client, _, _ string) error { return nil }

	if err := rollbackWithBundle(baseRollbackCommand()); err != nil {
		t.Fatalf("expected a half-finished rollback to be resumable, got %v", err)
	}
	if reverted == 0 {
		t.Fatal("expected the remaining steps to be reverted")
	}
}

func TestRollbackStillRefusesAnUnfinishedApply(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil }},
	})

	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) {
		j := successJournal()
		j.Status = "in_progress"
		return j, nil
	}

	err := rollbackWithBundle(baseRollbackCommand())
	if err == nil || !strings.Contains(err.Error(), "not marked successful") {
		t.Fatalf("expected an unfinished apply to stay refused, got %v", err)
	}
}

func TestClaimJournalFailureAbortsRollback(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	reverted := false
	installPlugins(t, map[string]fakeBehavior{
		"template": {rollback: func(pluginapi.Host, pluginapi.ObjectRecord) error {
			reverted = true
			return nil
		}},
	})

	saveRemoteJournal = func(*remote.Client, *Journal) error { return errors.New("read-only fs") }
	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureRollbackSudo = func(_ *remote.Client) error { return nil }
	loadRemoteJournal = func(_ *remote.Client, _ string) (*Journal, error) { return successJournal(), nil }

	err := rollbackWithBundle(baseRollbackCommand())
	if err == nil || !strings.Contains(err.Error(), "claim journal") {
		t.Fatalf("expected a claim failure, got %v", err)
	}
	if reverted {
		t.Fatal("expected nothing to be reverted when the journal could not be claimed")
	}
}
