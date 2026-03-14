package rollback

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestJournalSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }
	nowUTC = func() time.Time { return time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC) }

	j := NewJournal("example.com:22", "base-secure", "base-secure-ubuntu-24.04-lts")
	j.Status = "success"
	j.Steps = []StepRecord{
		{
			ID:           "s1",
			Type:         "template",
			RollbackMode: ModeDeterministic,
			Before: []ObjectRecord{
				{
					Kind: ObjectFile,
					File: &FileSnapshot{
						Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
						Existed:    true,
						Mode:       "0644",
						ContentB64: "YWJj",
					},
				},
			},
			After: []ObjectRecord{
				{
					Kind: ObjectFile,
					File: &FileSnapshot{
						Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
						Existed:    true,
						Mode:       "0600",
						ContentB64: "ZGVm",
					},
				},
			},
		},
	}

	if err := j.SaveLast(); err != nil {
		t.Fatalf("SaveLast failed: %v", err)
	}

	loaded, err := LoadLast("example.com:22")
	if err != nil {
		t.Fatalf("LoadLast failed: %v", err)
	}
	if loaded.Host != "example.com:22" || loaded.ProfileID != "base-secure" || loaded.Status != "success" {
		t.Fatalf("unexpected loaded journal: %+v", loaded)
	}
	if len(loaded.Steps) != 1 || loaded.Steps[0].ID != "s1" {
		t.Fatalf("unexpected loaded steps: %+v", loaded.Steps)
	}
	if len(loaded.Steps[0].Before) != 1 || len(loaded.Steps[0].After) != 1 {
		t.Fatalf("expected before/after snapshots to round-trip, got %+v", loaded.Steps[0])
	}
}

func TestJournalRemoveLast(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tmp := t.TempDir()
		restore := stubJournalHooks()
		defer restore()

		resolveStateDir = func() (string, error) { return tmp, nil }

		j := NewJournal("example.com", "base-secure", "profile")
		j.Status = "success"
		if err := j.SaveLast(); err != nil {
			t.Fatalf("SaveLast failed: %v", err)
		}
		if err := j.RemoveLast(); err != nil {
			t.Fatalf("RemoveLast failed: %v", err)
		}
		if _, err := LoadLast("example.com"); err == nil || !strings.Contains(err.Error(), "read rollback state") {
			t.Fatalf("expected removed state error, got %v", err)
		}
	})

	t.Run("nil journal", func(t *testing.T) {
		var j *Journal
		if err := j.RemoveLast(); err == nil || !strings.Contains(err.Error(), "journal is nil") {
			t.Fatalf("expected nil journal error, got %v", err)
		}
	})

	t.Run("non-empty host dir ignored", func(t *testing.T) {
		tmp := t.TempDir()
		restore := stubJournalHooks()
		defer restore()

		resolveStateDir = func() (string, error) { return tmp, nil }

		j := NewJournal("example.com", "base-secure", "profile")
		j.Status = "success"
		if err := j.SaveLast(); err != nil {
			t.Fatalf("SaveLast failed: %v", err)
		}
		hostDir := filepath.Join(tmp, sanitizeHostPath("example.com"))
		if err := os.WriteFile(filepath.Join(hostDir, "keep.txt"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write keep file: %v", err)
		}
		if err := j.RemoveLast(); err != nil {
			t.Fatalf("RemoveLast failed on non-empty dir: %v", err)
		}
		if _, err := os.Stat(filepath.Join(hostDir, "keep.txt")); err != nil {
			t.Fatalf("expected extra file to remain, got %v", err)
		}
	})
}

func TestSaveLast_ErrorPaths(t *testing.T) {
	t.Run("nil journal", func(t *testing.T) {
		var j *Journal
		if err := j.SaveLast(); err == nil || !strings.Contains(err.Error(), "journal is nil") {
			t.Fatalf("expected nil journal error, got %v", err)
		}
	})

	t.Run("state dir resolver error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return "", errors.New("boom") }
		j := NewJournal("host", "p", "dir")
		if err := j.SaveLast(); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected resolver error, got %v", err)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return t.TempDir(), nil }
		j := NewJournal("", "p", "dir")
		if err := j.SaveLast(); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host empty error, got %v", err)
		}
	})
}

func TestLoadLastVersionMismatch(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }

	hostDir := filepath.Join(tmp, sanitizeHostPath("host"))
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}

	data := []byte(`{"version":99,"host":"host"}`)
	if err := os.WriteFile(filepath.Join(hostDir, "last.json"), data, 0o644); err != nil {
		t.Fatalf("write last.json: %v", err)
	}

	if _, err := LoadLast("host"); err == nil || !strings.Contains(err.Error(), "unsupported rollback state version") {
		t.Fatalf("expected version mismatch error, got %v", err)
	}
}

func TestLoadLast_ErrorPaths(t *testing.T) {
	t.Run("state dir resolver error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return "", errors.New("boom") }
		if _, err := LoadLast("host"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected resolver error, got %v", err)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return t.TempDir(), nil }
		if _, err := LoadLast(""); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host required error, got %v", err)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		tmp := t.TempDir()
		resolveStateDir = func() (string, error) { return tmp, nil }
		hostDir := filepath.Join(tmp, sanitizeHostPath("host"))
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			t.Fatalf("mkdir host dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(hostDir, "last.json"), []byte("{bad"), 0o644); err != nil {
			t.Fatalf("write last.json: %v", err)
		}
		if _, err := LoadLast("host"); err == nil || !strings.Contains(err.Error(), "decode rollback state") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})
}

func TestDefaultStateDirAndSanitizeHost(t *testing.T) {
	t.Run("default uses env var", func(t *testing.T) {
		t.Setenv("HARDLINE_STATE_DIR", "/tmp/hardline-state")
		p, err := defaultStateDir()
		if err != nil {
			t.Fatalf("defaultStateDir failed: %v", err)
		}
		if p != "/tmp/hardline-state" {
			t.Fatalf("unexpected state dir: %q", p)
		}
	})

	t.Run("default uses cwd fallback", func(t *testing.T) {
		t.Setenv("HARDLINE_STATE_DIR", "")
		p, err := defaultStateDir()
		if err != nil {
			t.Fatalf("defaultStateDir failed: %v", err)
		}
		want := filepath.Join(os.TempDir(), "hardline", "runs")
		if p != want {
			t.Fatalf("unexpected fallback state dir: got=%q want=%q", p, want)
		}
	})

	t.Run("sanitize host", func(t *testing.T) {
		got := sanitizeHostPath("example.com:22 /prod")
		if strings.Contains(got, "/") || strings.Contains(got, ":") || strings.Contains(got, " ") {
			t.Fatalf("sanitizeHostPath did not sanitize: %q", got)
		}
		if got == "" {
			t.Fatal("expected non-empty sanitized host")
		}
	})
}

func TestStepRecordSnapshotsCloneCaptureState(t *testing.T) {
	before := pluginapi.CaptureResult{
		RollbackMode: ModeDeterministic,
		Objects: []pluginapi.ObjectRecord{
			{
				Kind: ObjectFile,
				File: &pluginapi.FileSnapshot{
					Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
					Existed:    true,
					Mode:       "0644",
					ContentB64: "YmVmb3Jl",
				},
			},
			{
				Kind: ObjectService,
				Service: &pluginapi.ServiceState{
					Unit:    "ssh",
					Enabled: true,
					Active:  true,
					Known:   true,
				},
			},
			{
				Kind: ObjectPackage,
				Package: &pluginapi.PackageState{
					Name:             "curl",
					WasInstalled:     true,
					Version:          "8.0.0",
					RequestedInstall: true,
				},
			},
		},
		Notes: []string{"captured before apply"},
	}

	step := NewStepRecordFromCapture("s1", "template", before)

	after := pluginapi.CaptureResult{
		Objects: []pluginapi.ObjectRecord{
			{
				Kind: ObjectFile,
				File: &pluginapi.FileSnapshot{
					Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
					Existed:    true,
					Mode:       "0600",
					ContentB64: "YWZ0ZXI=",
				},
			},
		},
	}
	step.SetAfterFromCapture(after)

	before.Objects[0].File.Path = "/mutated"
	before.Objects[1].Service.Unit = "mutated"
	before.Objects[2].Package.Name = "mutated"
	before.Notes[0] = "changed"
	after.Objects[0].File.Mode = "0666"

	if step.ID != "s1" || step.Type != "template" || step.RollbackMode != ModeDeterministic {
		t.Fatalf("unexpected step metadata: %+v", step)
	}
	if len(step.Before) != 3 || step.Before[0].File.Path != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" {
		t.Fatalf("expected cloned before file snapshot, got %+v", step.Before)
	}
	if step.Before[1].Service.Unit != "ssh" || step.Before[2].Package.Name != "curl" {
		t.Fatalf("expected cloned before service/package snapshots, got %+v", step.Before)
	}
	if len(step.After) != 1 || step.After[0].File.Mode != "0600" {
		t.Fatalf("expected cloned after file snapshot, got %+v", step.After)
	}
	if len(step.Notes) != 1 || step.Notes[0] != "captured before apply" {
		t.Fatalf("expected copied notes, got %+v", step.Notes)
	}
}

func TestStepRecordSetAfterFromCapture_NilReceiver(t *testing.T) {
	var step *StepRecord
	step.SetAfterFromCapture(pluginapi.CaptureResult{
		Objects: []pluginapi.ObjectRecord{{Kind: ObjectValidate, Message: "noop"}},
	})
}

func TestRemoteJournalSaveAndLoad(t *testing.T) {
	restore := stubJournalHooks()
	defer restore()

	resolveRemoteStatePath = func() string { return "/var/lib/hardline/runs/last.json" }

	j := NewJournal("example.com", "base-secure", "profile")
	j.Status = "success"

	var runCmds []string
	runRemoteRoot = func(_ *ssh.Client, cmd string) error {
		runCmds = append(runCmds, cmd)
		return nil
	}
	var wrotePath string
	var wroteMode os.FileMode
	var wroteData string
	newRemoteSFTPClient = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	writeRemoteRootFile = func(_ *ssh.Client, _ *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
		wrotePath = remotePath
		wroteMode = mode
		wroteData = string(data)
		return nil
	}
	readRemoteRootFile = func(_ *ssh.Client, remotePath string) (string, error) {
		if remotePath != wrotePath {
			t.Fatalf("unexpected remote path read: %q", remotePath)
		}
		return wroteData, nil
	}

	if err := SaveRemoteLast(nil, j); err != nil {
		t.Fatalf("SaveRemoteLast failed: %v", err)
	}
	if len(runCmds) != 1 || !strings.Contains(runCmds[0], "mkdir -p") {
		t.Fatalf("unexpected remote mkdir commands: %#v", runCmds)
	}
	if wrotePath != "/var/lib/hardline/runs/last.json" || wroteMode != 0o600 {
		t.Fatalf("unexpected remote write: path=%q mode=%#o", wrotePath, wroteMode)
	}

	loaded, err := LoadRemoteLast(nil)
	if err != nil {
		t.Fatalf("LoadRemoteLast failed: %v", err)
	}
	if loaded.Status != "success" || loaded.Host != "example.com" {
		t.Fatalf("unexpected remote journal: %+v", loaded)
	}
}

func TestRemoteJournalErrorPaths(t *testing.T) {
	t.Run("nil journal", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		if err := SaveRemoteLast(nil, nil); err == nil || !strings.Contains(err.Error(), "journal is nil") {
			t.Fatalf("expected nil journal error, got %v", err)
		}
	})

	t.Run("empty remote path", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func() string { return "" }
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "remote rollback state path is empty") {
			t.Fatalf("expected empty remote path error, got %v", err)
		}
		if _, err := LoadRemoteLast(nil); err == nil || !strings.Contains(err.Error(), "remote rollback state path is empty") {
			t.Fatalf("expected empty remote path load error, got %v", err)
		}
	})

	t.Run("mkdir failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func() string { return "/var/lib/hardline/runs/last.json" }
		runRemoteRoot = func(_ *ssh.Client, cmd string) error { return errors.New("mkdir boom") }
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "mkdir boom") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("new sftp failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func() string { return "/var/lib/hardline/runs/last.json" }
		runRemoteRoot = func(_ *ssh.Client, cmd string) error { return nil }
		newRemoteSFTPClient = func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("sftp boom") }
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("write failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func() string { return "/var/lib/hardline/runs/last.json" }
		runRemoteRoot = func(_ *ssh.Client, cmd string) error { return nil }
		newRemoteSFTPClient = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRemoteRootFile = func(_ *ssh.Client, _ *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
			return errors.New("write boom")
		}
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "write boom") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("read failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func() string { return "/var/lib/hardline/runs/last.json" }
		readRemoteRootFile = func(_ *ssh.Client, remotePath string) (string, error) { return "", errors.New("read boom") }
		if _, err := LoadRemoteLast(nil); err == nil || !strings.Contains(err.Error(), "read boom") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestDefaultRemoteStatePath(t *testing.T) {
	if got := defaultRemoteStatePath(); got != "/var/lib/hardline/runs/last.json" {
		t.Fatalf("unexpected default remote state path: %q", got)
	}
}

func stubJournalHooks() func() {
	prevNow := nowUTC
	prevStateDir := resolveStateDir
	prevRemoteStatePath := resolveRemoteStatePath
	prevRunRemoteRoot := runRemoteRoot
	prevReadRemoteRootFile := readRemoteRootFile
	prevWriteRemoteRootFile := writeRemoteRootFile
	prevNewRemoteSFTPClient := newRemoteSFTPClient
	return func() {
		nowUTC = prevNow
		resolveStateDir = prevStateDir
		resolveRemoteStatePath = prevRemoteStatePath
		runRemoteRoot = prevRunRemoteRoot
		readRemoteRootFile = prevReadRemoteRootFile
		writeRemoteRootFile = prevWriteRemoteRootFile
		newRemoteSFTPClient = prevNewRemoteSFTPClient
	}
}
