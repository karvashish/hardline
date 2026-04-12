package rollback

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

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

	j := NewJournal("example.com", "profile", "profile-dir")
	j.Status = "success"
	j.Steps = []StepRecord{
		{
			ID:           "template-step",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{
				{
					Kind: pluginapi.ObjectFile,
					File: &pluginapi.FileSnapshot{
						Path:    "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
						Existed: false,
					},
				},
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
	var cmds []string
	runRootCmd = func(_ *remote.Client, cmd string) error {
		cmds = append(cmds, cmd)
		return nil
	}

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
	if len(cmds) != 1 || !strings.Contains(cmds[0], "rm -f") {
		t.Fatalf("unexpected rollback commands: %#v", cmds)
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

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "success"
		j.Steps = []StepRecord{
			{
				ID:           "bad",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectFile, File: nil},
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

		err := RollbackSteps(nil, []StepRecord{
			{
				ID:           "bad",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectFile, File: nil},
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

		var cmds []string
		runRootCmd = func(_ *remote.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		err := RollbackSteps(nil, []StepRecord{
			{
				ID:           "template-step",
				Type:         "template",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{
						Kind: pluginapi.ObjectFile,
						File: &pluginapi.FileSnapshot{
							Path:    "/etc/nftables.d/99-hardline-itest.nft",
							Existed: false,
						},
					},
				},
			},
			{
				ID:           "service-step",
				Type:         "service",
				RollbackMode: pluginapi.ModeDeterministic,
				Before: []pluginapi.ObjectRecord{
					{
						Kind: pluginapi.ObjectService,
						Service: &pluginapi.ServiceState{
							Unit:    "nftables",
							Known:   true,
							Enabled: true,
							Active:  true,
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("RollbackSteps failed: %v", err)
		}

		if len(cmds) != 3 {
			t.Fatalf("expected 3 rollback commands, got %#v", cmds)
		}
		if !strings.Contains(cmds[0], "rm -f") {
			t.Fatalf("expected file removal before service restore, got %#v", cmds)
		}
		if !strings.Contains(cmds[1], "enable") || !strings.Contains(cmds[2], "restart") {
			t.Fatalf("unexpected service restore commands: %#v", cmds)
		}
	})
}

func TestRollbackStepsStrict(t *testing.T) {
	t.Run("best-effort errors are fatal in strict mode", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		err := executeRollbackSteps(nil, []StepRecord{
			{
				ID:           "pkg",
				Type:         "packages",
				RollbackMode: pluginapi.ModeBestEffort,
				Before: []pluginapi.ObjectRecord{
					{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: " "}},
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
	t.Run("best effort continues", func(t *testing.T) {
		step := StepRecord{
			ID:           "pkg",
			RollbackMode: pluginapi.ModeBestEffort,
			Before: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: ""}},
			},
		}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected best-effort step to continue, got %v", err)
		}
	})

	t.Run("deterministic fails", func(t *testing.T) {
		step := StepRecord{
			ID:           "file",
			RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectFile, File: nil},
			},
		}
		if err := rollbackStepWithMode(nil, step, false); err == nil {
			t.Fatal("expected deterministic step error")
		}
	})

	t.Run("noop", func(t *testing.T) {
		step := StepRecord{ID: "v", RollbackMode: pluginapi.ModeNoop}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected noop success, got %v", err)
		}
	})

	t.Run("after snapshots are ignored", func(t *testing.T) {
		step := StepRecord{
			ID:           "validate",
			RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectValidate, Message: "noop"},
			},
			After: []pluginapi.ObjectRecord{
				{Kind: pluginapi.ObjectFile, File: nil},
			},
		}
		if err := rollbackStepWithMode(nil, step, false); err != nil {
			t.Fatalf("expected rollback to use before snapshots only, got %v", err)
		}
	})
}

func TestRollbackObjectBranches(t *testing.T) {
	t.Run("service missing payload", func(t *testing.T) {
		err := rollbackObject(nil, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "missing snapshot payload") {
			t.Fatalf("expected service payload error, got %v", err)
		}
	})

	t.Run("package missing payload", func(t *testing.T) {
		err := rollbackObject(nil, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage})
		if err == nil || !strings.Contains(err.Error(), "missing snapshot payload") {
			t.Fatalf("expected package payload error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := rollbackObject(nil, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop success, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := rollbackObject(nil, pluginapi.ObjectRecord{Kind: "other"})
		if err == nil || !strings.Contains(err.Error(), "unsupported rollback object kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})
}

func TestRestoreFileAndServiceAndPackage(t *testing.T) {
	t.Run("restore file existing", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		var cmds []string
		runRootCmd = func(_ *remote.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		writeRootFile = func(_ *remote.Client, dest string, data []byte, mode os.FileMode) error {
			if dest != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" {
				t.Fatalf("unexpected dest: %q", dest)
			}
			if string(data) != "abc" {
				t.Fatalf("unexpected data: %q", string(data))
			}
			if mode != 0o640 {
				t.Fatalf("unexpected mode: %#o", mode)
			}
			return nil
		}

		snap := pluginapi.FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			Mode:       "0640",
			ContentB64: base64.StdEncoding.EncodeToString([]byte("abc")),
		}
		if err := restoreFile(nil, snap); err != nil {
			t.Fatalf("restoreFile failed: %v", err)
		}
		if len(cmds) == 0 || !strings.Contains(cmds[0], "mkdir -p") {
			t.Fatalf("expected mkdir command, got %#v", cmds)
		}
	})

	t.Run("restore file unmanaged path", func(t *testing.T) {
		err := restoreFile(nil, pluginapi.FileSnapshot{Path: "/tmp/99-hardline.conf", Existed: false})
		if err == nil || !strings.Contains(err.Error(), "outside /etc managed scope") {
			t.Fatalf("expected managed path error, got %v", err)
		}
	})

	t.Run("restore file decode error", func(t *testing.T) {
		err := restoreFile(nil, pluginapi.FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			ContentB64: "!!!",
		})
		if err == nil || !strings.Contains(err.Error(), "decode snapshot content") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})

	t.Run("restore file mkdir error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "mkdir -p") {
				return errors.New("mkdir boom")
			}
			return nil
		}
		err := restoreFile(nil, pluginapi.FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			ContentB64: base64.StdEncoding.EncodeToString([]byte("abc")),
		})
		if err == nil || !strings.Contains(err.Error(), "ensure directory") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("restore file write error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, _ string) error { return nil }
		writeRootFile = func(_ *remote.Client, _ string, _ []byte, _ os.FileMode) error {
			return errors.New("write boom")
		}
		err := restoreFile(nil, pluginapi.FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			ContentB64: base64.StdEncoding.EncodeToString([]byte("abc")),
		})
		if err == nil || !strings.Contains(err.Error(), "restore file") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("restore file remove", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		var cmd string
		runRootCmd = func(_ *remote.Client, in string) error {
			cmd = in
			return nil
		}
		if err := restoreFile(nil, pluginapi.FileSnapshot{
			Path:    "/etc/nftables.d/99-hardline-firewall.nft",
			Existed: false,
		}); err != nil {
			t.Fatalf("restoreFile failed: %v", err)
		}
		if !strings.Contains(cmd, "rm -f") {
			t.Fatalf("expected rm command, got %q", cmd)
		}
	})

	t.Run("service unknown error", func(t *testing.T) {
		err := restoreService(nil, pluginapi.ServiceState{Unit: "ssh", Known: false})
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("expected unknown service state error, got %v", err)
		}
	})

	t.Run("service empty unit", func(t *testing.T) {
		err := restoreService(nil, pluginapi.ServiceState{Known: true})
		if err == nil || !strings.Contains(err.Error(), "service unit is empty") {
			t.Fatalf("expected empty unit error, got %v", err)
		}
	})

	t.Run("service restore success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *remote.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		err := restoreService(nil, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: false})
		if err != nil {
			t.Fatalf("restoreService failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected service cmds: %#v", cmds)
		}
	})

	t.Run("service restore active restarts", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *remote.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		err := restoreService(nil, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true})
		if err != nil {
			t.Fatalf("restoreService failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "restart") {
			t.Fatalf("unexpected service cmds: %#v", cmds)
		}
	})

	t.Run("service enable error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "enable") {
				return errors.New("enable boom")
			}
			return nil
		}
		err := restoreService(nil, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true})
		if err == nil || !strings.Contains(err.Error(), "enabled state") {
			t.Fatalf("expected enabled state error, got %v", err)
		}
	})

	t.Run("service active error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "restart") || strings.Contains(cmd, "stop") {
				return errors.New("active boom")
			}
			return nil
		}
		err := restoreService(nil, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: false, Active: true})
		if err == nil || !strings.Contains(err.Error(), "active state") {
			t.Fatalf("expected active state error, got %v", err)
		}
	})

	t.Run("package rollback", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *remote.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		if err := rollbackPackageBestEffort(nil, pluginapi.PackageState{
			Name:             "fail2ban",
			RequestedInstall: true,
			WasInstalled:     false,
		}); err != nil {
			t.Fatalf("rollbackPackageBestEffort install->purge failed: %v", err)
		}

		if err := rollbackPackageBestEffort(nil, pluginapi.PackageState{
			Name:           "telnet",
			RequestedPurge: true,
			WasInstalled:   true,
			Version:        "1.2.3",
		}); err != nil {
			t.Fatalf("rollbackPackageBestEffort purge->install failed: %v", err)
		}

		if len(cmds) < 2 {
			t.Fatalf("expected rollback package commands, got %#v", cmds)
		}
	})

	t.Run("package purge error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "apt-get purge") {
				return errors.New("purge boom")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, pluginapi.PackageState{
			Name:             "pkg",
			RequestedInstall: true,
			WasInstalled:     false,
		})
		if err == nil || !strings.Contains(err.Error(), "purge package") {
			t.Fatalf("expected purge package error, got %v", err)
		}
	})

	t.Run("package reinstall fallback", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		count := 0
		runRootCmd = func(_ *remote.Client, cmd string) error {
			count++
			if strings.Contains(cmd, "pkg=1.0") {
				return errors.New("version unavailable")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, pluginapi.PackageState{
			Name:           "pkg",
			RequestedPurge: true,
			WasInstalled:   true,
			Version:        "1.0",
		})
		if err != nil {
			t.Fatalf("rollbackPackageBestEffort failed: %v", err)
		}
		if count < 2 {
			t.Fatalf("expected versioned + fallback install commands, count=%d", count)
		}
	})

	t.Run("package reinstall fallback fails", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "apt-get install -y") {
				return errors.New("install boom")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, pluginapi.PackageState{
			Name:           "pkg",
			RequestedPurge: true,
			WasInstalled:   true,
			Version:        "1.0",
		})
		if err == nil || !strings.Contains(err.Error(), "reinstall package") {
			t.Fatalf("expected reinstall package error, got %v", err)
		}
	})

	t.Run("package empty name", func(t *testing.T) {
		err := rollbackPackageBestEffort(nil, pluginapi.PackageState{Name: " "})
		if err == nil || !strings.Contains(err.Error(), "package name is empty") {
			t.Fatalf("expected empty package name error, got %v", err)
		}
	})
}

func TestEnforceManagedPathUsesPluginAPI(t *testing.T) {
	if err := pluginapi.EnforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.conf"); err != nil {
		t.Fatalf("expected managed path to pass, got %v", err)
	}
	if err := pluginapi.EnforceManagedPath("/tmp/99-hardline-ssh.conf"); err == nil {
		t.Fatal("expected /tmp path to fail")
	}
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

	var cmds []string
	runRootCmd = func(_ *remote.Client, cmd string) error {
		cmds = append(cmds, cmd)
		return nil
	}

	if err := RollbackSteps(nil, steps); err != nil {
		t.Fatalf("RollbackSteps failed: %v", err)
	}

	// Only the changed step should produce a rollback command; idempotent step is skipped.
	if len(cmds) != 1 || !strings.Contains(cmds[0], "rm -f") {
		t.Fatalf("expected exactly one rollback command for changed step, got %#v", cmds)
	}
}

func TestCheckStepConflicts(t *testing.T) {
	validB64 := base64.StdEncoding.EncodeToString([]byte("expected-content"))

	t.Run("no conflict when current matches journal after", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "expected-content", nil }

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: validB64}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("conflict when current differs from journal after", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "something-else", nil }

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: validB64}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) != 1 || !strings.Contains(got[0], "modified since apply") {
			t.Fatalf("expected one conflict, got %v", got)
		}
	})

	t.Run("skips when after.Existed is false", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts for deleted-file after, got %v", got)
		}
	})

	t.Run("skips invalid base64 in journal", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: "!!!not-valid-base64!!!"}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts for invalid base64, got %v", got)
		}
	})

	t.Run("conflict when file unreadable but journal says existed", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "", errors.New("permission denied") }

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: validB64}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) != 1 || !strings.Contains(got[0], "cannot be read") {
			t.Fatalf("expected unreadable-file conflict, got %v", got)
		}
	})

	t.Run("executeRollbackSteps blocks on conflict without force", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "tampered", nil }

		step := StepRecord{
			ID:           "s",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
			After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: validB64}}},
		}
		err := executeRollbackSteps(nil, []StepRecord{step}, false, false, false)
		if err == nil || !strings.Contains(err.Error(), "force-rollback") {
			t.Fatalf("expected force-rollback error, got %v", err)
		}
	})

	t.Run("executeRollbackSteps proceeds with force on conflict", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "tampered", nil }
		runRootCmd = func(_ *remote.Client, _ string) error { return nil }

		step := StepRecord{
			ID:           "s",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before:       []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: false}}},
			After:        []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Existed: true, ContentB64: validB64}}},
		}
		if err := executeRollbackSteps(nil, []StepRecord{step}, false, false, true); err != nil {
			t.Fatalf("expected force rollback to succeed, got %v", err)
		}
	})
}

func TestCheckStepConflicts_ServiceAndPackage(t *testing.T) {
	t.Run("service: no conflict when state matches journal", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, _ string) error { return nil } // is-enabled and is-active both succeed

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("service: conflict when enabled state differs", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error {
			if strings.Contains(cmd, "is-enabled") {
				return errors.New("disabled") // service is now disabled
			}
			return nil // is-active succeeds
		}

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) == 0 || !strings.Contains(got[0], "enabled state") {
			t.Fatalf("expected enabled-state conflict, got %v", got)
		}
	})

	t.Run("service: skipped when Known=false", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nginx", Known: false}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts for Unknown service, got %v", got)
		}
	})

	t.Run("service: skipped when unit is empty", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "", Known: true}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts for empty unit, got %v", got)
		}
	})

	t.Run("package: no conflict when installed state matches", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, _ string) error { return nil } // dpkg -s succeeds = installed

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("package: conflict when installed state differs", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, _ string) error { return errors.New("not installed") }

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) == 0 || !strings.Contains(got[0], "changed since apply") {
			t.Fatalf("expected package conflict, got %v", got)
		}
	})

	t.Run("package: skipped when name is empty", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "", WasInstalled: true}},
		}}
		if got := checkStepConflicts(nil, step); len(got) != 0 {
			t.Fatalf("expected no conflicts for empty package name, got %v", got)
		}
	})
}

func TestRollbackWrapperExitHook(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	runRollbackCommand = func(cli.Command) error { return errors.New("boom") }
	exitCode := 0
	exitProcess = func(code int) { exitCode = code }

	Rollback(cli.Command{})
	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
}

func TestCheckStepConflicts_PackageVersionMismatch(t *testing.T) {
	t.Run("version mismatch detected", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error { return nil } // dpkg -s succeeds = installed
		runRootWithOutputCmd = func(_ *remote.Client, cmd string) (string, error) {
			return "2.0.0", nil // current version differs from journal
		}

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: "1.0.0"}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) != 1 || !strings.Contains(got[0], "upgraded since apply") {
			t.Fatalf("expected version conflict, got %v", got)
		}
	})

	t.Run("version matches no conflict", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error { return nil }
		runRootWithOutputCmd = func(_ *remote.Client, cmd string) (string, error) {
			return "1.0.0", nil
		}

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: "1.0.0"}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("empty journal version skips check", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *remote.Client, cmd string) error { return nil }
		runRootWithOutputCmd = func(_ *remote.Client, cmd string) (string, error) {
			return "2.0.0", nil
		}

		step := StepRecord{After: []pluginapi.ObjectRecord{
			{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: ""}},
		}}
		got := checkStepConflicts(nil, step)
		if len(got) != 0 {
			t.Fatalf("expected no conflicts for empty version, got %v", got)
		}
	})
}

func stubRollbackHooks() func() {
	prevNewSSH := newSSHClient
	prevRunRoot := runRootCmd
	prevWriteRoot := writeRootFile
	prevEnsureSudo := ensureRollbackSudo
	prevLoadRemoteJournal := loadRemoteJournal
	prevDeleteJournal := deleteJournal
	prevReadRemoteFile := readRemoteFile
	prevRunRootWithOutput := runRootWithOutputCmd
	prevLoadProfileID := loadProfileID
	prevRunRollbackCommand := runRollbackCommand
	prevExit := exitProcess

	// Default stub: no conflicts (current content matches journal after).
	readRemoteFile = func(_ *remote.Client, _ string) (string, error) { return "", nil }
	runRootWithOutputCmd = func(_ *remote.Client, _ string) (string, error) { return "", nil }

	return func() {
		newSSHClient = prevNewSSH
		runRootCmd = prevRunRoot
		writeRootFile = prevWriteRoot
		ensureRollbackSudo = prevEnsureSudo
		loadRemoteJournal = prevLoadRemoteJournal
		deleteJournal = prevDeleteJournal
		readRemoteFile = prevReadRemoteFile
		runRootWithOutputCmd = prevRunRootWithOutput
		loadProfileID = prevLoadProfileID
		runRollbackCommand = prevRunRollbackCommand
		exitProcess = prevExit
	}
}
