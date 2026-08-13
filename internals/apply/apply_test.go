package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestApply_ErrorPaths(t *testing.T) {
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

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) {
			return nil, errors.New("dial failed")
		}

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "connect failed") {
			t.Fatalf("expected connect failed error, got %v", err)
		}
	})

	t.Run("missing verified bundle", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		if err := Apply(context.Background(), c, nil); err == nil ||
			!strings.Contains(err.Error(), "verified profile bundle") {
			t.Fatal("expected Apply to refuse to run without a verified bundle")
		}
	})

	t.Run("version command failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{}, 0, errors.New("bad version") }

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "hardline version check failed") {
			t.Fatalf("expected hardline version check failed error, got %v", err)
		}
	})

	t.Run("compare semver failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = &profile.Profile{MinHardline: "x.y.z", ProfileSchema: 1}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, errors.New("bad semver") }

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "invalid profile.min_hardline value") {
			t.Fatalf("expected invalid min_hardline error, got %v", err)
		}
	})

	t.Run("binary too old", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = &profile.Profile{MinHardline: "2.0.0", ProfileSchema: 1}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return -1, nil }

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "too old") {
			t.Fatalf("expected too old error, got %v", err)
		}
	})

	t.Run("schema too new", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 2}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "profile schema") {
			t.Fatalf("expected schema too new error, got %v", err)
		}
	})

	t.Run("required plugin validation failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		ensureApplyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error {
			return errors.New("required plugin missing")
		}

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "step validation failed") {
			t.Fatalf("expected step validation error, got %v", err)
		}
	})

	t.Run("apply profile failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
			return errors.New("boom")
		}

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected apply profile error, got %v", err)
		}
	})

	t.Run("local rollback journal save failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return nil }
		applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{ID: "p", MinHardline: "1.0.0", Schema: 1})
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
			return nil
		}

		bad := cli.Command{
			Profile: "profile",
			Host:    "",
			User:    "deployer",
			KeyPath: "/tmp/key",
			Debug:   true,
		}
		err := applyWithBundle(context.Background(), bad)
		if err == nil || !strings.Contains(err.Error(), "persist local rollback journal failed") {
			t.Fatalf("expected local rollback journal persist error, got %v", err)
		}
	})

	t.Run("sudo preflight failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
		ensureApplySudo = func(_ *remote.Client) error { return errors.New("sudo denied") }

		err := applyWithBundle(context.Background(), c)
		if err == nil || !strings.Contains(err.Error(), "sudo preflight failed") {
			t.Fatalf("expected sudo preflight error, got %v", err)
		}
	})
}

func TestApply_Success(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) {
		if cfg.Host != c.Host || cfg.User != c.User || cfg.KeyPath != c.KeyPath {
			t.Fatalf("unexpected connection config: %+v", cfg)
		}
		return nil, nil
	}
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return nil }

	removedLocalJournal := false
	removeRunnerJournal = func(journal *rollback.Journal) error {
		removedLocalJournal = true
		return nil
	}

	called := false
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		called = true
		if p.MinHardline != "1.0.0" {
			t.Fatalf("unexpected profile passed to apply: %+v", p)
		}
		if journal == nil {
			t.Fatal("expected rollback journal to be passed")
		}
		return nil
	}

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !called {
		t.Fatal("expected runApply to be called")
	}
	if !removedLocalJournal {
		t.Fatal("expected local rollback journal cleanup on successful apply")
	}
}

func TestApplyCommand_PassesRuntimeOverrides(t *testing.T) {
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
	applyBundleOverrides = map[string]json.RawMessage{"ssh_port": json.RawMessage(`2222`)}

	newSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{
		MinHardline:      "1.0.0",
		Schema:           1,
		AllowedOverrides: []string{"ssh_port"},
	})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return nil }
	removeRunnerJournal = func(journal *rollback.Journal) error { return nil }
	runApplyProfile = func(_ context.Context, _ *remote.Client, p *profile.Profile, _ *rollback.Journal) error {
		if string(p.RuntimeOverrides()["ssh_port"]) != "2222" {
			t.Fatalf("expected runtime overrides on profile, got %+v", p.RuntimeOverrides())
		}
		return nil
	}

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("applyCommand failed: %v", err)
	}
}

func TestApplyCommand_KeepLocalRollback(t *testing.T) {
	t.Setenv("HARDLINE_STATE_DIR", t.TempDir())

	restore := stubApplyDeps()
	defer restore()

	c := cli.Command{
		Profile:           "profile",
		Host:              "host",
		User:              "user",
		KeyPath:           "/tmp/key",
		KeepLocalRollback: true,
		Debug:             true,
	}

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		return nil
	}
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return nil }

	saveCalls := 0
	saveRunnerJournal = func(journal *rollback.Journal) error {
		saveCalls++
		return nil
	}
	removeRunnerJournal = func(journal *rollback.Journal) error {
		t.Fatal("removeRunnerJournal should not be called when keep flag is set")
		return nil
	}

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("applyCommand failed: %v", err)
	}
	if saveCalls < 2 {
		t.Fatalf("expected local rollback journal to be saved at least twice, got %d", saveCalls)
	}
}

func TestApplyCommand_TargetJournalSaveFailed(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		return nil
	}
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return errors.New("remote boom") }

	err := applyWithBundle(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "persist target rollback journal failed") {
		t.Fatalf("expected target rollback journal save error, got %v", err)
	}
}

func TestApplyCommand_ApplyFailureAndLocalJournalSaveFailure(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		return errors.New("apply boom")
	}

	saveCalls := 0
	saveRunnerJournal = func(journal *rollback.Journal) error {
		saveCalls++
		if saveCalls == 2 {
			return errors.New("save boom")
		}
		return nil
	}

	err := applyWithBundle(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "apply boom; persist local rollback journal failed: save boom") {
		t.Fatalf("expected combined apply/save failure, got %v", err)
	}
}

func TestApplyCommand_SuccessNonDebugCleanupWarning(t *testing.T) {
	t.Setenv("HARDLINE_STATE_DIR", t.TempDir())

	restore := stubApplyDeps()
	defer restore()

	c := cli.Command{
		Profile: "profile",
		Host:    "host",
		User:    "user",
		KeyPath: "/tmp/key",
		Debug:   false,
	}

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		return nil
	}
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return nil }
	removeRunnerJournal = func(journal *rollback.Journal) error { return errors.New("cleanup boom") }

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("expected success with cleanup warning, got %v", err)
	}
}

func TestApplyCommand_KeepLocalRollbackWarning(t *testing.T) {
	t.Setenv("HARDLINE_STATE_DIR", t.TempDir())

	restore := stubApplyDeps()
	defer restore()

	c := cli.Command{
		Profile:           "profile",
		Host:              "host",
		User:              "user",
		KeyPath:           "/tmp/key",
		KeepLocalRollback: true,
		Debug:             true,
	}

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
		return nil
	}
	saveTargetJournal = func(client *remote.Client, journal *rollback.Journal) error { return nil }

	saveCalls := 0
	saveRunnerJournal = func(journal *rollback.Journal) error {
		saveCalls++
		if saveCalls == 2 {
			return errors.New("keep boom")
		}
		return nil
	}

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("expected success with keep warning, got %v", err)
	}
}

func TestApplyProfile_StepLoop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		seen := []string{}
		captureCalls := 0
		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			captureCalls++
			message := "before:" + step.ID
			if captureCalls%2 == 0 {
				message = "after:" + step.ID
			}
			return pluginapi.CaptureResult{
				RollbackMode: pluginapi.ModeDeterministic,
				Objects: []pluginapi.ObjectRecord{
					{
						Kind:    pluginapi.ObjectValidate,
						Message: message,
					},
				},
			}, nil
		}
		saveCalls := 0
		saveRunnerJournal = func(journal *rollback.Journal) error {
			saveCalls++
			return nil
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step, _ map[string]bool) error {
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

		if err := applyProfile(context.Background(), nil, p, journal); err != nil {
			t.Fatalf("applyProfile failed: %v", err)
		}
		if strings.Join(seen, ",") != "s1,s2" {
			t.Fatalf("unexpected step order: %v", seen)
		}
		if len(journal.Steps) != 2 {
			t.Fatalf("expected 2 journal steps, got %d", len(journal.Steps))
		}
		if saveCalls != 4 {
			t.Fatalf("expected rollback journal to be persisted before and after each captured step, got %d", saveCalls)
		}
		if got := journal.Steps[0].Before[0].Message; got != "before:s1" {
			t.Fatalf("unexpected first step before snapshot: %+v", journal.Steps[0].Before)
		}
		if got := journal.Steps[0].After[0].Message; got != "after:s1" {
			t.Fatalf("unexpected first step after snapshot: %+v", journal.Steps[0].After)
		}
		if got := journal.Steps[1].Before[0].Message; got != "before:s2" {
			t.Fatalf("unexpected second step before snapshot: %+v", journal.Steps[1].Before)
		}
		if got := journal.Steps[1].After[0].Message; got != "after:s2" {
			t.Fatalf("unexpected second step after snapshot: %+v", journal.Steps[1].After)
		}
	})

	t.Run("step error bubbles", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			return errors.New("step boom")
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(context.Background(), nil, p, nil)
		if err == nil || !strings.Contains(err.Error(), "step boom") {
			t.Fatalf("expected step error, got %v", err)
		}
	})

	t.Run("journal save failure during capture", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		}
		saveRunnerJournal = func(journal *rollback.Journal) error { return errors.New("journal boom") }
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			t.Fatal("runStep should not be reached when journal persistence fails")
			return nil
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(context.Background(), nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "persist local rollback journal failed") {
			t.Fatalf("expected journal save error, got %v", err)
		}
	})

	t.Run("step error triggers automatic rollback", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			return errors.New("step boom")
		}
		rollbackCalled := false
		runRollbackStep = func(_ *remote.Client, steps []rollback.StepRecord) error {
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

		err := applyProfile(context.Background(), nil, p, rollback.NewJournal("example.com", "p", "profile"))
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

		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			return errors.New("step boom")
		}
		runRollbackStep = func(_ *remote.Client, _ []rollback.StepRecord) error {
			return errors.New("rollback boom")
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(context.Background(), nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "automatic rollback failed") {
			t.Fatalf("expected automatic rollback failure error, got %v", err)
		}
	})

	t.Run("post-apply capture failure triggers automatic rollback", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		captureCalls := 0
		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step) (pluginapi.CaptureResult, error) {
			captureCalls++
			if captureCalls == 1 {
				return pluginapi.CaptureResult{
					RollbackMode: pluginapi.ModeDeterministic,
					Objects: []pluginapi.ObjectRecord{
						{Kind: pluginapi.ObjectValidate, Message: "before"},
					},
				}, nil
			}
			return pluginapi.CaptureResult{}, errors.New("post capture boom")
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			return nil
		}
		rollbackCalled := false
		runRollbackStep = func(_ *remote.Client, steps []rollback.StepRecord) error {
			rollbackCalled = true
			if len(steps) != 1 {
				t.Fatalf("expected one step in rollback, got %d", len(steps))
			}
			if len(steps[0].Before) != 1 || steps[0].Before[0].Message != "before" {
				t.Fatalf("unexpected rollback before snapshot: %+v", steps[0].Before)
			}
			if len(steps[0].After) != 0 {
				t.Fatalf("expected no post-apply snapshot after capture failure, got %+v", steps[0].After)
			}
			return nil
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}}},
			},
		}

		err := applyProfile(context.Background(), nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "capture post-apply state") || !strings.Contains(err.Error(), "automatic rollback completed") {
			t.Fatalf("expected post-capture rollback error, got %v", err)
		}
		if !rollbackCalled {
			t.Fatal("expected rollback after post-apply capture failure")
		}
	})

	t.Run("snapshot capture error bubbles", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		registry := pluginapi.NewRegistry()
		if err := registry.Register(pluginapi.Plugin{
			Name:               "failing",
			InternalValidation: true,
			Validate:           func(profile.Step, map[string]json.RawMessage) error { return nil },
			Apply:              func(pluginapi.Context, profile.Step) error { return nil },
			Plan: func(pluginapi.Context, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, nil
			},
			Capture: func(pluginapi.Context, profile.Step) (pluginapi.CaptureResult, error) {
				return pluginapi.CaptureResult{}, errors.New("capture failed")
			},
			Rollback:       func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
			DetectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil },
		}); err != nil {
			t.Fatalf("register plugin failed: %v", err)
		}
		prevCapture := runCaptureStepRecord
		defer func() {
			runCaptureStepRecord = prevCapture
		}()
		runCaptureStepRecord = func(_ *pluginapi.Registry, client *remote.Client, p *profile.Profile, s profile.Step) (pluginapi.CaptureResult, error) {
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

		err := applyProfile(context.Background(), nil, p, rollback.NewJournal("example.com", "p", "profile"))
		if err == nil || !strings.Contains(err.Error(), "capture failed") {
			t.Fatalf("expected capture error, got %v", err)
		}
	})

	t.Run("cancelled context rolls back completed steps", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		runCaptureStepRecord = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step) (pluginapi.CaptureResult, error) {
			return pluginapi.CaptureResult{}, nil
		}
		runStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, _ profile.Step, _ map[string]bool) error {
			return nil
		}
		saveRunnerJournal = func(journal *rollback.Journal) error { return nil }
		rollbackCalled := false
		runRollbackStep = func(_ *remote.Client, steps []rollback.StepRecord) error {
			rollbackCalled = true
			return nil
		}
		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{Steps: []profile.Step{{ID: "s1", Plugin: "unknown"}, {ID: "s2", Plugin: "unknown"}}},
			},
		}
		journal := rollback.NewJournal("example.com", "p", "profile")
		journal.Steps = append(journal.Steps, rollback.StepRecord{ID: "prior"})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := applyProfile(ctx, nil, p, journal)
		if err == nil || !strings.Contains(err.Error(), "interrupted") {
			t.Fatalf("expected interrupted error, got %v", err)
		}
		if !rollbackCalled {
			t.Fatal("expected rollback to run for completed steps")
		}
		if journal.Status != "interrupted" {
			t.Fatalf("expected journal status interrupted, got %q", journal.Status)
		}
	})
}

func stubApplyDeps() func() {
	prevNewSSH := newSSHClient
	prevVersion := versionCmd
	prevCompare := compareSemVer
	prevEnsureSudo := ensureApplySudo
	prevEnsurePlugins := ensureApplyPlugins
	prevRunApplyProfile := runApplyProfile
	prevRunCapture := runCaptureStepRecord
	prevRunRollbackStep := runRollbackStep
	prevSaveRunnerJournal := saveRunnerJournal
	prevRemoveRunnerJournal := removeRunnerJournal
	prevSaveTargetJournal := saveTargetJournal
	prevRunStep := runStep
	prevAcquireLock := acquireMutationLock
	prevReleaseLock := releaseMutationLock
	applyBundleProfile = &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}
	applyBundleOverrides = nil
	return func() {
		newSSHClient = prevNewSSH
		versionCmd = prevVersion
		compareSemVer = prevCompare
		ensureApplySudo = prevEnsureSudo
		ensureApplyPlugins = prevEnsurePlugins
		runApplyProfile = prevRunApplyProfile
		runCaptureStepRecord = prevRunCapture
		runRollbackStep = prevRunRollbackStep
		saveRunnerJournal = prevSaveRunnerJournal
		removeRunnerJournal = prevRemoveRunnerJournal
		saveTargetJournal = prevSaveTargetJournal
		runStep = prevRunStep
		acquireMutationLock = prevAcquireLock
		releaseMutationLock = prevReleaseLock
	}
}

func TestApplyCommand_LockContention(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	acquireMutationLock = func(_ *remote.Client) error {
		return fmt.Errorf("another hardline apply is already running on this host; if stale, run: sudo rmdir %s", remote.MutationLockDir)
	}

	err := applyWithBundle(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("expected lock contention error, got %v", err)
	}
}

func TestApplyCommand_LockReleasedOnSuccess(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	acquireMutationLock = func(_ *remote.Client) error { return nil }
	released := false
	releaseMutationLock = func(_ *remote.Client) error {
		released = true
		return nil
	}
	applyBundleProfile = mustLoadApplyFixtureProfile(t, applyProfileFixture{MinHardline: "1.0.0", Schema: 1})
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	runApplyProfile = func(_ context.Context, _ *remote.Client, _ *profile.Profile, _ *rollback.Journal) error { return nil }
	saveTargetJournal = func(_ *remote.Client, _ *rollback.Journal) error { return nil }
	removeRunnerJournal = func(_ *rollback.Journal) error { return nil }

	if err := applyWithBundle(context.Background(), c); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if !released {
		t.Fatal("expected apply lock to be released after success")
	}
}

func TestApplyCommand_LockReleasedOnFailure(t *testing.T) {
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

	newSSHClient = func(cfg connection.Config) (*remote.Client, error) { return nil, nil }
	ensureApplySudo = func(_ *remote.Client) error { return nil }
	acquireMutationLock = func(_ *remote.Client) error { return nil }
	released := false
	releaseMutationLock = func(_ *remote.Client) error {
		released = true
		return nil
	}
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }
	saveRunnerJournal = func(_ *rollback.Journal) error { return nil }
	runApplyProfile = func(context.Context, *remote.Client, *profile.Profile, *rollback.Journal) error {
		return errors.New("apply boom")
	}

	err := applyWithBundle(context.Background(), c)
	if err == nil || !strings.Contains(err.Error(), "apply boom") {
		t.Fatalf("expected apply error, got %v", err)
	}
	if !released {
		t.Fatal("expected apply lock to be released after failure")
	}
}

type applyProfileFixture struct {
	ID               string
	MinHardline      string
	Schema           int
	AllowedOverrides []string
}

func mustLoadApplyFixtureProfile(t *testing.T, f applyProfileFixture) *profile.Profile {
	t.Helper()

	id := f.ID
	if id == "" {
		id = "p"
	}
	allowedOverrides := f.AllowedOverrides
	if allowedOverrides == nil {
		allowedOverrides = []string{}
	}
	allowedOverridesJSON, err := json.Marshal(allowedOverrides)
	if err != nil {
		t.Fatalf("marshal allowed_overrides: %v", err)
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
  "templates": [],
  "allowed_overrides": ` + string(allowedOverridesJSON) + `
}`
	p, err := profile.LoadFromBundle(dir, map[string][]byte{"profile.json": []byte(body)})
	if err != nil {
		t.Fatalf("load fixture profile failed: %v", err)
	}
	return p
}

var (
	applyBundleProfile   *profile.Profile
	applyBundleOverrides map[string]json.RawMessage
)

func applyWithBundle(ctx context.Context, c cli.Command) error {
	return Apply(ctx, c, &verify.VerifiedBundle{
		ProfileDir:     c.Profile,
		ManifestDigest: "digest",
		Profile:        applyBundleProfile,
		Overrides:      applyBundleOverrides,
	})
}

func TestJournalledRollbackFidelity(t *testing.T) {
	cases := []struct {
		name    string
		journal *rollback.Journal
		want    string
	}{
		{name: "no journal", want: "AVAILABLE"},
		{
			name: "deterministic steps only",
			journal: &rollback.Journal{Steps: []rollback.StepRecord{
				{ID: "s1", RollbackMode: pluginapi.ModeDeterministic},
			}},
			want: "AVAILABLE",
		},
		{
			name: "a best-effort step is named",
			journal: &rollback.Journal{Steps: []rollback.StepRecord{
				{ID: "s1", RollbackMode: pluginapi.ModeDeterministic},
				{ID: "s2", RollbackMode: pluginapi.ModeBestEffort},
			}},
			want: "BEST-EFFORT for 1 step(s)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := journalledRollbackFidelity(tc.journal)
			if got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}
