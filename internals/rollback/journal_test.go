package rollback

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
			Objects: []ObjectRecord{
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
		if err := j.SaveLast(); err == nil || !strings.Contains(err.Error(), "host is empty") {
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
		if !strings.HasSuffix(p, "/.hardline/runs") {
			t.Fatalf("unexpected fallback state dir: %q", p)
		}
	})

	t.Run("default getwd error", func(t *testing.T) {
		t.Setenv("HARDLINE_STATE_DIR", "")
		oldWD, err := os.Getwd()
		if err != nil {
			t.Fatalf("Getwd failed: %v", err)
		}
		bad := t.TempDir()
		if err := os.Chdir(bad); err != nil {
			t.Fatalf("chdir bad dir: %v", err)
		}
		if err := os.RemoveAll(bad); err != nil {
			t.Fatalf("remove bad dir: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Chdir(oldWD)
		})
		if _, err := defaultStateDir(); err == nil || !strings.Contains(err.Error(), "resolve working directory") {
			t.Fatalf("expected getwd error, got %v", err)
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

func stubJournalHooks() func() {
	prevNow := nowUTC
	prevStateDir := resolveStateDir
	return func() {
		nowUTC = prevNow
		resolveStateDir = prevStateDir
	}
}
