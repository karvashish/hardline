package rollback

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestJournalSaveAndLoad(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }
	nowUTC = func() time.Time { return time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC) }

	j := NewJournal("example.com:22", "base-secure", "starter-secure-ubuntu-24.04-lts")
	j.Status = "success"
	j.Steps = []StepRecord{
		{
			ID:           "s1",
			Type:         "template",
			RollbackMode: pluginapi.ModeDeterministic,
			Before: []pluginapi.ObjectRecord{
				{
					Kind: pluginapi.ObjectFile,
					File: &pluginapi.FileSnapshot{
						Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
						Existed:    true,
						Mode:       "0644",
						ContentB64: "YWJj",
					},
				},
			},
			After: []pluginapi.ObjectRecord{
				{
					Kind: pluginapi.ObjectFile,
					File: &pluginapi.FileSnapshot{
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

	loaded, err := LoadLast("example.com:22", "base-secure")
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
		if _, err := LoadLast("example.com", "base-secure"); err == nil || !strings.Contains(err.Error(), "read rollback state") {
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
		hostDir := filepath.Join(tmp, sanitizePath("example.com"))
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

	t.Run("empty profile ID", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return t.TempDir(), nil }
		j := NewJournal("host", "", "dir")
		if err := j.SaveLast(); err == nil || !strings.Contains(err.Error(), "profile ID is required") {
			t.Fatalf("expected profile ID empty error, got %v", err)
		}
	})
}

func TestLoadLastVersionMismatch(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }

	hostDir := filepath.Join(tmp, sanitizePath("host"))
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatalf("mkdir host dir: %v", err)
	}

	data := []byte(`{"version":99,"host":"host"}`)
	if err := os.WriteFile(filepath.Join(hostDir, "testprofile.json"), data, 0o644); err != nil {
		t.Fatalf("write testprofile.json: %v", err)
	}

	if _, err := LoadLast("host", "testprofile"); err == nil || !strings.Contains(err.Error(), "unsupported rollback state version") {
		t.Fatalf("expected version mismatch error, got %v", err)
	}
}

func TestLoadLast_ErrorPaths(t *testing.T) {
	t.Run("state dir resolver error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return "", errors.New("boom") }
		if _, err := LoadLast("host", "p"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected resolver error, got %v", err)
		}
	})

	t.Run("empty host", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return t.TempDir(), nil }
		if _, err := LoadLast("", "p"); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host required error, got %v", err)
		}
	})

	t.Run("empty profile ID", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveStateDir = func() (string, error) { return t.TempDir(), nil }
		if _, err := LoadLast("host", ""); err == nil || !strings.Contains(err.Error(), "profile ID is required") {
			t.Fatalf("expected profile ID required error, got %v", err)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		tmp := t.TempDir()
		resolveStateDir = func() (string, error) { return tmp, nil }
		hostDir := filepath.Join(tmp, sanitizePath("host"))
		if err := os.MkdirAll(hostDir, 0o755); err != nil {
			t.Fatalf("mkdir host dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(hostDir, "p.json"), []byte("{bad"), 0o644); err != nil {
			t.Fatalf("write p.json: %v", err)
		}
		if _, err := LoadLast("host", "p"); err == nil || !strings.Contains(err.Error(), "decode rollback state") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})
}

func TestJournalChecksumRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }
	nowUTC = func() time.Time { return time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC) }

	j := NewJournal("host", "profile", "dir")
	j.Status = "success"
	if err := j.SaveLast(); err != nil {
		t.Fatalf("SaveLast failed: %v", err)
	}

	loaded, err := LoadLast("host", "profile")
	if err != nil {
		t.Fatalf("LoadLast failed on valid journal: %v", err)
	}
	if loaded.Checksum == "" {
		t.Fatal("expected checksum to be set on saved journal")
	}
	if loaded.Status != "success" {
		t.Fatalf("unexpected status after roundtrip: %q", loaded.Status)
	}
}

func TestJournalChecksumTamperDetection(t *testing.T) {
	tmp := t.TempDir()
	restore := stubJournalHooks()
	defer restore()

	resolveStateDir = func() (string, error) { return tmp, nil }
	nowUTC = func() time.Time { return time.Date(2026, 3, 7, 14, 0, 0, 0, time.UTC) }

	j := NewJournal("host", "profile", "dir")
	j.Status = "success"
	if err := j.SaveLast(); err != nil {
		t.Fatalf("SaveLast failed: %v", err)
	}

	_, lastPath, _, err := localLastPaths("host", "profile")
	if err != nil {
		t.Fatalf("localLastPaths failed: %v", err)
	}
	data, err := os.ReadFile(lastPath)
	if err != nil {
		t.Fatalf("read journal file: %v", err)
	}
	tampered := strings.Replace(string(data), `"success"`, `"in_progress"`, 1)
	if err := os.WriteFile(lastPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered journal: %v", err)
	}

	_, err = LoadLast("host", "profile")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected checksum mismatch error on tampered journal, got %v", err)
	}
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
		got := sanitizePath("example.com:22 /prod")
		if strings.Contains(got, "/") || strings.Contains(got, ":") || strings.Contains(got, " ") {
			t.Fatalf("sanitizePath did not sanitize: %q", got)
		}
		if got == "" {
			t.Fatal("expected non-empty sanitized host")
		}
	})
}

func TestStepRecordSnapshotsCloneCaptureState(t *testing.T) {
	before := pluginapi.CaptureResult{
		RollbackMode: pluginapi.ModeDeterministic,
		Objects: []pluginapi.ObjectRecord{
			{
				Kind: pluginapi.ObjectFile,
				File: &pluginapi.FileSnapshot{
					Path:       "/etc/ssh/sshd_config.d/99-hardline-ssh.conf",
					Existed:    true,
					Mode:       "0644",
					ContentB64: "YmVmb3Jl",
				},
			},
			{
				Kind: pluginapi.ObjectService,
				Service: &pluginapi.ServiceState{
					Unit:    "ssh",
					Enabled: true,
					Active:  true,
					Known:   true,
				},
			},
			{
				Kind: pluginapi.ObjectPackage,
				Package: &pluginapi.PackageState{
					Name:             "curl",
					WasInstalled:     true,
					Version:          "8.0.0",
					RequestedInstall: true,
				},
			},
			{
				Kind: pluginapi.ObjectRuntimePolicy,
				RuntimePolicy: &pluginapi.RuntimePolicy{
					Name:  "nft list ruleset",
					State: "table inet hardline",
				},
			},
		},
		Notes: []string{"captured before apply"},
	}

	step := NewStepRecordFromCapture("s1", "template", before)

	after := pluginapi.CaptureResult{
		Objects: []pluginapi.ObjectRecord{
			{
				Kind: pluginapi.ObjectFile,
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
	before.Objects[3].RuntimePolicy.State = "mutated"
	before.Notes[0] = "changed"
	after.Objects[0].File.Mode = "0666"

	if step.ID != "s1" || step.Type != "template" || step.RollbackMode != pluginapi.ModeDeterministic {
		t.Fatalf("unexpected step metadata: %+v", step)
	}
	if len(step.Before) != 4 || step.Before[0].File.Path != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" {
		t.Fatalf("expected cloned before file snapshot, got %+v", step.Before)
	}
	if step.Before[1].Service.Unit != "ssh" || step.Before[2].Package.Name != "curl" {
		t.Fatalf("expected cloned before service/package snapshots, got %+v", step.Before)
	}
	if step.Before[3].RuntimePolicy.State != "table inet hardline" {
		t.Fatalf("the journalled runtime policy still aliases the capture, got %+v", step.Before)
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
		Objects: []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, Message: "noop"}},
	})
}

func TestRemoteJournalSaveAndLoad(t *testing.T) {
	restore := stubJournalHooks()
	defer restore()

	resolveRemoteStatePath = func(profileID, runID string) string {
		return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
	}

	j := NewJournal("example.com", "base-secure", "profile")
	j.Status = "success"

	var runCmds []string
	runRemoteRoot = func(_ *remote.Client, cmd string) error {
		runCmds = append(runCmds, cmd)
		return nil
	}
	var wrotePath string
	var wroteMode os.FileMode
	var wroteData string
	writeRemoteRootFile = func(_ *remote.Client, remotePath string, data []byte, mode os.FileMode) error {
		wrotePath = remotePath
		wroteMode = mode
		wroteData = string(data)
		return nil
	}
	runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) {
		return path.Base(wrotePath) + "\n", nil
	}
	readRemoteRootFile = func(_ *remote.Client, remotePath string) (string, error) {
		if remotePath != wrotePath {
			t.Fatalf("unexpected remote path read: %q (expected %q)", remotePath, wrotePath)
		}
		return wroteData, nil
	}

	if err := SaveRemoteLast(nil, j); err != nil {
		t.Fatalf("SaveRemoteLast failed: %v", err)
	}
	if len(runCmds) != 1 || !strings.Contains(runCmds[0], "mkdir -p") {
		t.Fatalf("unexpected remote mkdir commands: %#v", runCmds)
	}
	if !strings.HasPrefix(wrotePath, "/var/lib/hardline/runs/base-secure/") || wroteMode != 0o600 {
		t.Fatalf("unexpected remote write: path=%q mode=%#o", wrotePath, wroteMode)
	}

	loaded, err := LoadRemoteLast(nil, "base-secure")
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
		resolveRemoteStatePath = func(string, string) string { return "" }
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "remote rollback state path is empty") {
			t.Fatalf("expected empty remote path error, got %v", err)
		}
	})

	t.Run("no journal found", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(profileID, runID string) string {
			return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
		}
		runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) { return "", nil }
		if _, err := LoadRemoteLast(nil, "p"); err == nil || !strings.Contains(err.Error(), "no journal found") {
			t.Fatalf("expected no journal found error, got %v", err)
		}
	})

	t.Run("list journals error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(profileID, runID string) string {
			return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
		}
		runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) { return "", errors.New("list boom") }
		if _, err := LoadRemoteLast(nil, "p"); err == nil || !strings.Contains(err.Error(), "list boom") {
			t.Fatalf("expected list error, got %v", err)
		}
	})

	t.Run("mkdir failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(string, string) string { return "/var/lib/hardline/runs/p/run.json" }
		runRemoteRoot = func(_ *remote.Client, cmd string) error { return errors.New("mkdir boom") }
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "mkdir boom") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("write failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(string, string) string { return "/var/lib/hardline/runs/p/run.json" }
		runRemoteRoot = func(_ *remote.Client, cmd string) error { return nil }
		writeRemoteRootFile = func(_ *remote.Client, remotePath string, data []byte, mode os.FileMode) error {
			return errors.New("write boom")
		}
		if err := SaveRemoteLast(nil, NewJournal("host", "p", "dir")); err == nil || !strings.Contains(err.Error(), "write boom") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("read failed", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(profileID, runID string) string {
			return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
		}
		runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) { return "20260810T101500.000000000Z.json\n", nil }
		readRemoteRootFile = func(_ *remote.Client, remotePath string) (string, error) { return "", errors.New("read boom") }
		if _, err := LoadRemoteLast(nil, "p"); err == nil || !strings.Contains(err.Error(), "read boom") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestDefaultRemoteStatePath(t *testing.T) {
	runID := "20260307T140000.000000000Z"
	if got := defaultRemoteStatePath("myprofile", runID); got != "/var/lib/hardline/runs/myprofile/"+runID+".json" {
		t.Fatalf("unexpected default remote state path: %q", got)
	}
	if got := defaultRemoteStatePath("", runID); got != "/var/lib/hardline/runs/unknown/"+runID+".json" {
		t.Fatalf("expected fallback to unknown/ for empty profileID, got %q", got)
	}
}

func TestDeleteRemoteJournal(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(profileID, runID string) string {
			return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
		}
		var deletedPath string
		runRemoteRoot = func(_ *remote.Client, cmd string) error {
			deletedPath = cmd
			return nil
		}
		if err := DeleteRemoteJournal(nil, "base-secure", "20260307T140000Z"); err != nil {
			t.Fatalf("DeleteRemoteJournal failed: %v", err)
		}
		if !strings.Contains(deletedPath, "base-secure") || !strings.Contains(deletedPath, "20260307T140000Z") {
			t.Fatalf("unexpected delete command: %q", deletedPath)
		}
	})

	t.Run("empty path", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(string, string) string { return "" }
		if err := DeleteRemoteJournal(nil, "p", "run"); err == nil || !strings.Contains(err.Error(), "remote rollback state path is empty") {
			t.Fatalf("expected empty path error, got %v", err)
		}
	})

	t.Run("rm error", func(t *testing.T) {
		restore := stubJournalHooks()
		defer restore()
		resolveRemoteStatePath = func(string, string) string { return "/var/lib/hardline/runs/p/run.json" }
		runRemoteRoot = func(_ *remote.Client, _ string) error { return errors.New("rm boom") }
		if err := DeleteRemoteJournal(nil, "p", "run"); err == nil || !strings.Contains(err.Error(), "rm boom") {
			t.Fatalf("expected rm error, got %v", err)
		}
	})
}

func stubJournalHooks() func() {
	prevNow := nowUTC
	prevStateDir := resolveStateDir
	prevRemoteStatePath := resolveRemoteStatePath
	prevRunRemoteRoot := runRemoteRoot
	prevRunRemoteRootWithOutput := runRemoteRootWithOutput
	prevReadRemoteRootFile := readRemoteRootFile
	prevWriteRemoteRootFile := writeRemoteRootFile
	return func() {
		nowUTC = prevNow
		resolveStateDir = prevStateDir
		resolveRemoteStatePath = prevRemoteStatePath
		runRemoteRoot = prevRunRemoteRoot
		runRemoteRootWithOutput = prevRunRemoteRootWithOutput
		readRemoteRootFile = prevReadRemoteRootFile
		writeRemoteRootFile = prevWriteRemoteRootFile
	}
}

func TestLoadRemoteLast_IgnoresForeignFilenames(t *testing.T) {
	restore := stubJournalHooks()
	defer restore()

	resolveRemoteStatePath = func(profileID, runID string) string {
		return "/var/lib/hardline/runs/" + profileID + "/" + runID + ".json"
	}

	t.Run("sorts past a lexically larger foreign name", func(t *testing.T) {
		runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "20260810T101500.000000000Z.json\nzz-attacker.json\nnotes.txt\n", nil
		}
		var readPath string
		readRemoteRootFile = func(_ *remote.Client, p string) (string, error) {
			readPath = p
			return "", errors.New("stop here")
		}
		if _, err := LoadRemoteLast(nil, "p"); err == nil {
			t.Fatal("expected the stubbed read to fail")
		}
		if !strings.HasSuffix(readPath, "20260810T101500.000000000Z.json") {
			t.Fatalf("expected the well-formed journal to be selected, got %q", readPath)
		}
	})

	t.Run("no well-formed name is no journal", func(t *testing.T) {
		runRemoteRootWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "run.json\nbackup.json.bak\n", nil
		}
		if _, err := LoadRemoteLast(nil, "p"); err == nil || !strings.Contains(err.Error(), "no journal found") {
			t.Fatalf("expected no journal found, got %v", err)
		}
	})
}
