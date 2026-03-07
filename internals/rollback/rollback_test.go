package rollback

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestRollbackCommand_TargetValidationAndLoadError(t *testing.T) {
	t.Run("unsupported target", func(t *testing.T) {
		if err := rollbackCommand(cli.Command{Profile: "previous"}); err == nil || !strings.Contains(err.Error(), "unsupported rollback target") {
			t.Fatalf("expected unsupported target error, got %v", err)
		}
	})

	t.Run("missing state", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()

		stateDir := t.TempDir()
		resolveStateDir = func() (string, error) { return stateDir, nil }
		newSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, nil }

		err := rollbackCommand(cli.Command{
			Profile: "last",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "read rollback state") {
			t.Fatalf("expected read state error, got %v", err)
		}
	})
}

func TestRollbackCommand_Success(t *testing.T) {
	restore := stubRollbackHooks()
	defer restore()

	stateDir := t.TempDir()
	resolveStateDir = func() (string, error) { return stateDir, nil }

	j := NewJournal("example.com", "profile", "profile-dir")
	j.Status = "success"
	j.Steps = []StepRecord{
		{
			ID:           "template-step",
			Type:         "template",
			RollbackMode: ModeDeterministic,
			Objects: []ObjectRecord{
				{
					Kind: ObjectFile,
					File: &FileSnapshot{
						Path:    "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
						Existed: false,
					},
				},
			},
		},
	}
	if err := j.SaveLast(); err != nil {
		t.Fatalf("SaveLast failed: %v", err)
	}

	var seenCfg connection.Config
	newSSHClient = func(cfg connection.Config) (*ssh.Client, error) {
		seenCfg = cfg
		return nil, nil
	}
	var cmds []string
	runRootCmd = func(_ *ssh.Client, cmd string) error {
		cmds = append(cmds, cmd)
		return nil
	}

	err := rollbackCommand(cli.Command{
		Profile: "last",
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
		stateDir := t.TempDir()
		resolveStateDir = func() (string, error) { return stateDir, nil }

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "failed"
		if err := j.SaveLast(); err != nil {
			t.Fatalf("SaveLast failed: %v", err)
		}

		newSSHClient = func(connection.Config) (*ssh.Client, error) {
			t.Fatal("newSSHClient should not be called when status is not success")
			return nil, nil
		}
		err := rollbackCommand(cli.Command{
			Profile: "last",
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
		stateDir := t.TempDir()
		resolveStateDir = func() (string, error) { return stateDir, nil }

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "success"
		if err := j.SaveLast(); err != nil {
			t.Fatalf("SaveLast failed: %v", err)
		}

		newSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, errors.New("dial") }
		err := rollbackCommand(cli.Command{
			Profile: "last",
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
		stateDir := t.TempDir()
		resolveStateDir = func() (string, error) { return stateDir, nil }

		j := NewJournal("example.com", "profile", "profile-dir")
		j.Status = "success"
		j.Steps = []StepRecord{
			{
				ID:           "bad",
				Type:         "template",
				RollbackMode: ModeDeterministic,
				Objects: []ObjectRecord{
					{Kind: ObjectFile, File: nil},
				},
			},
		}
		if err := j.SaveLast(); err != nil {
			t.Fatalf("SaveLast failed: %v", err)
		}

		newSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, nil }
		err := rollbackCommand(cli.Command{
			Profile: "last",
			Host:    "example.com",
			User:    "root",
			KeyPath: "/tmp/key",
			Debug:   true,
		})
		if err == nil || !strings.Contains(err.Error(), "rollback step") {
			t.Fatalf("expected rollback step failure, got %v", err)
		}
	})
}

func TestRollbackStepModes(t *testing.T) {
	t.Run("best effort continues", func(t *testing.T) {
		step := StepRecord{
			ID:           "pkg",
			RollbackMode: ModeBestEffort,
			Objects: []ObjectRecord{
				{Kind: ObjectPackage, Package: &PackageState{Name: ""}},
			},
		}
		if err := rollbackStep(nil, step); err != nil {
			t.Fatalf("expected best-effort step to continue, got %v", err)
		}
	})

	t.Run("deterministic fails", func(t *testing.T) {
		step := StepRecord{
			ID:           "file",
			RollbackMode: ModeDeterministic,
			Objects: []ObjectRecord{
				{Kind: ObjectFile, File: nil},
			},
		}
		if err := rollbackStep(nil, step); err == nil {
			t.Fatal("expected deterministic step error")
		}
	})

	t.Run("noop", func(t *testing.T) {
		step := StepRecord{ID: "v", RollbackMode: ModeNoop}
		if err := rollbackStep(nil, step); err != nil {
			t.Fatalf("expected noop success, got %v", err)
		}
	})
}

func TestRollbackObjectBranches(t *testing.T) {
	t.Run("service missing payload", func(t *testing.T) {
		err := rollbackObject(nil, ObjectRecord{Kind: ObjectService})
		if err == nil || !strings.Contains(err.Error(), "missing snapshot payload") {
			t.Fatalf("expected service payload error, got %v", err)
		}
	})

	t.Run("package missing payload", func(t *testing.T) {
		err := rollbackObject(nil, ObjectRecord{Kind: ObjectPackage})
		if err == nil || !strings.Contains(err.Error(), "missing snapshot payload") {
			t.Fatalf("expected package payload error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := rollbackObject(nil, ObjectRecord{Kind: ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop success, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := rollbackObject(nil, ObjectRecord{Kind: "other"})
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
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
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

		snap := FileSnapshot{
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
		err := restoreFile(nil, FileSnapshot{Path: "/tmp/99-hardline.conf", Existed: false})
		if err == nil || !strings.Contains(err.Error(), "outside /etc managed scope") {
			t.Fatalf("expected managed path error, got %v", err)
		}
	})

	t.Run("restore file decode error", func(t *testing.T) {
		err := restoreFile(nil, FileSnapshot{
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
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "mkdir -p") {
				return errors.New("mkdir boom")
			}
			return nil
		}
		err := restoreFile(nil, FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			ContentB64: base64.StdEncoding.EncodeToString([]byte("abc")),
		})
		if err == nil || !strings.Contains(err.Error(), "ensure directory") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("restore file sftp error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, errors.New("sftp boom") }
		err := restoreFile(nil, FileSnapshot{
			Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
			Existed:    true,
			ContentB64: base64.StdEncoding.EncodeToString([]byte("abc")),
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("restore file write error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error {
			return errors.New("write boom")
		}
		err := restoreFile(nil, FileSnapshot{
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
		runRootCmd = func(_ *ssh.Client, in string) error {
			cmd = in
			return nil
		}
		if err := restoreFile(nil, FileSnapshot{
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
		err := restoreService(nil, ServiceState{Unit: "ssh", Known: false})
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("expected unknown service state error, got %v", err)
		}
	})

	t.Run("service empty unit", func(t *testing.T) {
		err := restoreService(nil, ServiceState{Known: true})
		if err == nil || !strings.Contains(err.Error(), "service unit is empty") {
			t.Fatalf("expected empty unit error, got %v", err)
		}
	})

	t.Run("service restore success", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}
		err := restoreService(nil, ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: false})
		if err != nil {
			t.Fatalf("restoreService failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected service cmds: %#v", cmds)
		}
	})

	t.Run("service enable error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "enable") {
				return errors.New("enable boom")
			}
			return nil
		}
		err := restoreService(nil, ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true})
		if err == nil || !strings.Contains(err.Error(), "enabled state") {
			t.Fatalf("expected enabled state error, got %v", err)
		}
	})

	t.Run("service active error", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "start") || strings.Contains(cmd, "stop") {
				return errors.New("active boom")
			}
			return nil
		}
		err := restoreService(nil, ServiceState{Unit: "ssh", Known: true, Enabled: false, Active: true})
		if err == nil || !strings.Contains(err.Error(), "active state") {
			t.Fatalf("expected active state error, got %v", err)
		}
	})

	t.Run("package rollback", func(t *testing.T) {
		restore := stubRollbackHooks()
		defer restore()
		var cmds []string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}

		if err := rollbackPackageBestEffort(nil, PackageState{
			Name:             "fail2ban",
			RequestedInstall: true,
			WasInstalled:     false,
		}); err != nil {
			t.Fatalf("rollbackPackageBestEffort install->purge failed: %v", err)
		}

		if err := rollbackPackageBestEffort(nil, PackageState{
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
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "apt-get purge") {
				return errors.New("purge boom")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, PackageState{
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
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			count++
			if strings.Contains(cmd, "pkg=1.0") {
				return errors.New("version unavailable")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, PackageState{
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
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "apt-get install -y") {
				return errors.New("install boom")
			}
			return nil
		}
		err := rollbackPackageBestEffort(nil, PackageState{
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
		err := rollbackPackageBestEffort(nil, PackageState{Name: " "})
		if err == nil || !strings.Contains(err.Error(), "package name is empty") {
			t.Fatalf("expected empty package name error, got %v", err)
		}
	})
}

func TestEnforceManagedPath(t *testing.T) {
	if err := enforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.conf"); err != nil {
		t.Fatalf("expected managed path to pass, got %v", err)
	}
	if err := enforceManagedPath("/tmp/99-hardline-ssh.conf"); err == nil {
		t.Fatal("expected /tmp path to fail")
	}
	if err := enforceManagedPath("/etc/ssh/sshd_config.d/10-ssh.conf"); err == nil {
		t.Fatal("expected low-priority path to fail")
	}
	if err := enforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.txt"); err == nil {
		t.Fatal("expected unsupported extension to fail")
	}
	if err := enforceManagedPath("/etc/ssh/sshd_config.d/../99-hardline-ssh.conf"); err == nil {
		t.Fatal("expected non-normalized path to fail")
	}
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

func stubRollbackHooks() func() {
	prevNewSSH := newSSHClient
	prevRunRoot := runRootCmd
	prevWriteRoot := writeRootFile
	prevNewSFTP := newSFTPClient
	prevRunRollbackCommand := runRollbackCommand
	prevExit := exitProcess
	prevStateDir := resolveStateDir

	return func() {
		newSSHClient = prevNewSSH
		runRootCmd = prevRunRoot
		writeRootFile = prevWriteRoot
		newSFTPClient = prevNewSFTP
		runRollbackCommand = prevRunRollbackCommand
		exitProcess = prevExit
		resolveStateDir = prevStateDir
	}
}
