package apply

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestApplyCommand_ErrorPaths(t *testing.T) {
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

	t.Run("apply profile failed", func(t *testing.T) {
		restore := stubApplyDeps()
		defer restore()

		newSSHClient = func(cfg connection.Config) (*ssh.Client, error) { return nil, nil }
		loadProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}, nil
		}
		versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
		compareSemVer = func(a, b string) (int, error) { return 0, nil }
		runApplyProfile = func(client *ssh.Client, p *profile.Profile) error { return errors.New("boom") }

		err := applyCommand(c)
		if err == nil || !strings.Contains(err.Error(), "apply failed") {
			t.Fatalf("expected apply failed error, got %v", err)
		}
	})
}

func TestApplyCommand_Success(t *testing.T) {
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
	loadProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{MinHardline: "1.0.0", ProfileSchema: 1}, nil
	}
	versionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	compareSemVer = func(a, b string) (int, error) { return 0, nil }

	called := false
	runApplyProfile = func(client *ssh.Client, p *profile.Profile) error {
		called = true
		if p.MinHardline != "1.0.0" {
			t.Fatalf("unexpected profile passed to apply: %+v", p)
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
				{Steps: []profile.Step{{ID: "s1", Type: "validate"}}},
				{Steps: []profile.Step{{ID: "s2", Type: "validate"}}},
			},
		}

		if err := applyProfile(nil, p); err != nil {
			t.Fatalf("applyProfile failed: %v", err)
		}
		if strings.Join(seen, ",") != "s1,s2" {
			t.Fatalf("unexpected step order: %v", seen)
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
				{Steps: []profile.Step{{ID: "s1", Type: "validate"}}},
			},
		}

		err := applyProfile(nil, p)
		if err == nil || !strings.Contains(err.Error(), "step boom") {
			t.Fatalf("expected step error, got %v", err)
		}
	})
}

func stubApplyDeps() func() {
	prevNewSSH := newSSHClient
	prevLoad := loadProfile
	prevVersion := versionCmd
	prevCompare := compareSemVer
	prevRunApplyProfile := runApplyProfile
	prevRunApplyCommand := runApplyCommand
	prevExit := exitProcess
	prevRunStep := runStep

	return func() {
		newSSHClient = prevNewSSH
		loadProfile = prevLoad
		versionCmd = prevVersion
		compareSemVer = prevCompare
		runApplyProfile = prevRunApplyProfile
		runApplyCommand = prevRunApplyCommand
		exitProcess = prevExit
		runStep = prevRunStep
	}
}
