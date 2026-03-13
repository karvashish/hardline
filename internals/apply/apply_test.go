package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestApplyCommand_ErrorPaths(t *testing.T) {
	t.Setenv("HARDLINE_STATE_DIR", t.TempDir())

	c := cli.Command{
		Profile: "profile",
		Host:    "example.com",
		User:    "deployer",
		KeyPath: "/tmp/key",
		Debug:   true,
	}

	t.Run("connect failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) {
			return nil, errors.New("dial failed")
		}

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "connect failed") {
			t.Fatalf("expected connect failed error, got %v", err)
		}
	})

	t.Run("profile load failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) { return nil, errors.New("no profile") }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "profile load failed") {
			t.Fatalf("expected profile load failed error, got %v", err)
		}
	})

	t.Run("version command failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{}, 0, errors.New("bad version") }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "hardline version check failed") {
			t.Fatalf("expected hardline version check failed error, got %v", err)
		}
	})

	t.Run("compare semver failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "x.y.z", ProfileSchema: 1}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, errors.New("bad semver") }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "invalid profile.min_hardline value") {
			t.Fatalf("expected invalid min_hardline error, got %v", err)
		}
	})

	t.Run("binary too old", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "2.0.0", ProfileSchema: 1}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return -1, nil }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "too old") {
			t.Fatalf("expected too old error, got %v", err)
		}
	})

	t.Run("schema too new", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 2}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "profile schema") {
			t.Fatalf("expected schema too new error, got %v", err)
		}
	})

	t.Run("profile validation failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "profile validation failed") {
			t.Fatalf("expected profile validation error, got %v", err)
		}
	})

	t.Run("apply profile failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1}), nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		runApplyProfile = func(client *ssh.Client, p *profile.Profile, journal *rollback.Journal) error {
			return errors.New("boom")
		}

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "apply failed") {
			t.Fatalf("expected apply failed error, got %v", err)
		}
	})

	t.Run("rollback journal save failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return mustLoadApplyFixtureProfile(t, applyProfileFixture{ID: "p", MinHardline: "1.0.0", Schema: 1}), nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		runApplyProfile = func(client *ssh.Client, p *profile.Profile, journal *rollback.Journal) error { return nil }

		bad := cli.Command{
			Profile: "profile",
			Host:    "",
			User:    "deployer",
			KeyPath: "/tmp/key",
			Debug:   true,
		}
		err := applyCommand(bad)
		if err == nil || !strings.Contains(err.Error(), "persist rollback journal failed") {
			t.Fatalf("expected rollback journal persist error, got %v", err)
		}
	})

	t.Run("sudo preflight failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *ssh.Client) error { return errors.New("sudo denied") }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "sudo preflight failed") {
			t.Fatalf("expected sudo preflight error, got %v", err)
		}
	})
}

func TestApplyCommand_Success(t *testing.T) {
	t.Setenv("HARDLINE_STATE_DIR", t.TempDir())

	restore := stubApplyDeps()
	defer restore()

	c := cli.Command{
		Profile: "profile",
		Host:    "host",
		User:    "user",
		KeyPath: "/tmp/key",
		Debug:   true,
	}

	newSSHClient = func(cfg connection.Config) (*ssh.Client, error) {
		if cfg.Host != c.Host || cfg.User != c.User || cfg.KeyPath != c.KeyPath {
			t.Fatalf("unexpected connection config: %+v", cfg)
		}
		return nil, nil
	}
	ensureApplySudo = func(_ *ssh.Client) error { return nil }
	loadProfile = func(string) (*profile.Profile, error) {
		return mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1}), nil
	}
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }

	called := false
	runApplyProfile = func(client *ssh.Client, p *profile.Profile, journal *rollback.Journal) error {
		called = true
		if p.MinHardline != "1.0.0" {
			t.Fatalf("unexpected profile passed to apply: %+v", p)
		}
		if journal == nil {
			t.Fatal("expected rollback journal to be passed")
		}
		return nil
	}

	if err := applyCommand(c); err != nil {
		t.Fatalf("applyCommand failed: %v", err)
	}
	if !called {
		t.Fatal("expected runApply to be called")
	}
}

func TestApply_UsesWrapperAndExitHook(t *testing.T) {
	t.Run("no exit on success", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runApplyCommand = func(cli.Command) error { return nil }

		exitCalls := 0
		exitProcess = func(code int) {
			exitCalls++
			if code != 1 {
				t.Fatalf("unexpected exit code: %d", code)
			}
		}

		Apply(cli.Command{})
		if exitCalls != 0 {
			t.Fatalf("expected no exit calls, got %d", exitCalls)
		}
	})

	t.Run("exit on failure", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runApplyCommand = func(cli.Command) error { return errors.New("boom") }

		exitCalls := 0
		exitProcess = func(code int) {
			exitCalls++
			if code != 1 {
				t.Fatalf("unexpected exit code: %d", code)
			}
		}

		Apply(cli.Command{})
		if exitCalls != 1 {
			t.Fatalf("expected one exit call, got %d", exitCalls)
		}
	})
}

func TestApplyProfile_StepLoop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		seen := []string{}
		runStep = func(_ *ssh.Client, _ *profile.Profile, step profile.Step) error {
			seen = append(seen, step.ID)
			return nil
		}

		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
				{Steps: []profile.Step{{ID: "s2", Plugin: "unknown"}}},
			},
		}
		journal := rollback.NewJournal("example.com", "p", "profile")

		if err := applyProfile(nil, p, journal); err != nil {
			t.Fatalf("applyProfile failed: %v", err)
		}
		if strings.Join(seen, ",") != "s1,s2" {
			t.Fatalf("unexpected step order: %v", seen)
		}
		if len(journal.Steps) != 2 {
			t.Fatalf("expected 2 journal steps, got %d", len(journal.Steps))
		}
	})

	t.Run("step error bubbles", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runStep = func(_ *ssh.Client, _ *profile.Profile, _ profile.Step) error {
			return errors.New("step boom")
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(nil, p, nil)
		if err == nil || !strings.Contains(err.Error(), "step boom") {
			t.Fatalf("expected step error, got %v", err)
		}
	})

	t.Run("step error triggers automatic rollback", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runStep = func(_ *ssh.Client, _ *profile.Profile, _ profile.Step) error {
			return errors.New("step boom")
		}
		rollbackCalled := false
		runRollbackStep = func(_ *ssh.Client, steps []rollback.StepRecord) error {
			rollbackCalled = true
			if len(steps) != 1 {
				t.Fatalf("expected one captured step for rollback, got %d", len(steps))
			}
			return nil
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "automatic rollback completed") {
			t.Fatalf("expected automatic rollback completion error, got %v", err)
		}
		if !rollbackCalled {
			t.Fatal("expected automatic rollback to be invoked")
		}
	})

	t.Run("step error and rollback failure", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runStep = func(_ *ssh.Client, _ *profile.Profile, _ profile.Step) error {
			return errors.New("step boom")
		}
		runRollbackStep = func(_ *ssh.Client, _ []rollback.StepRecord) error {
			return errors.New("rollback boom")
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "automatic rollback failed") {
			t.Fatalf("expected automatic rollback failure error, got %v", err)
		}
	})

	t.Run("snapshot capture error bubbles", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		registry := pluginapi.NewRegistry()
		if err := registry.Register(pluginapi.Plugin{
			Name:               "failing",
			InternalValidation: true,
			Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
			Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, nil
			},
			Rollback: func(pluginapi.RollbackContext, profile.Step) (rollback.StepRecord, error) {
				return rollback.StepRecord{}, errors.New("capture failed")
			},
		}); err != nil {
			t.Fatalf("register plugin failed: %v", err)
		}
		prevCapture := runCaptureStepRecord
		defer func() {
			runCaptureStepRecord = prevCapture
		}()
		runCaptureStepRecord = func(client *ssh.Client, p *profile.Profile, s profile.Step) (rollback.StepRecord, error) {
			return captureStepRecordWithRegistry(registry, client, p, s)
		}

		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{
							ID:     "bad-step",
							Plugin: "failing",
						},
					},
				},
			},
		}

		err := applyProfile(nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "capture failed") {
			t.Fatalf("expected capture error, got %v", err)
		}
	})
}

func stubApplyDeps() func() {
	prevNewSSH := newSSHClient
	prevLoad := loadProfile
	prevVersion := versionCmd
	prevCompare := compareSemVer
	prevEnsureSudo := ensureApplySudo
	prevRunApplyProfile := runApplyProfile
	prevRunRollbackStep := runRollbackStep
	prevRunApplyCommand := runApplyCommand
	prevExit := exitProcess
	prevRunStep := runStep
	return func() {
		newSSHClient = prevNewSSH
		loadProfile = prevLoad
		versionCmd = prevVersion
		compareSemVer = prevCompare
		ensureApplySudo = prevEnsureSudo
		runApplyProfile = prevRunApplyProfile
		runRollbackStep = prevRunRollbackStep
		runApplyCommand = prevRunApplyCommand
		exitProcess = prevExit
		runStep = prevRunStep
	}
}

type applyProfileFixture struct {
	ID          string
	MinHardline string
	Schema      int
}

func mustLoadApplyFixtureProfile(t *testing.T, f applyProfileFixture) *profile.Profile {
	t.Helper()

	id := f.ID
	if id == "" {
		id = "p"
	}

	dir := t.TempDir()
	body := `{
  "id": "` + id + `",
  "display_name": "Profile",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": ` + strconv.Itoa(f.Schema) + `,
  "min_hardline": "` + f.MinHardline + `",
  "actions": [],
  "templates": []
}`
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}

	p, err := profile.Load(dir)
	if err != nil {
		t.Fatalf("load fixture profile failed: %v", err)
	}
	return p
}
