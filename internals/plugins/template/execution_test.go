package template

import (
	"errors"
	"fmt"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApply(t *testing.T) {
	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load template error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/missing.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load template error, got %v", err)
		}
	})

	t.Run("new sftp error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return errors.New("boom") },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "mkdir -p") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success explicit mode", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		var gotDest string
		var gotData string
		var gotMode os.FileMode
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Mode: "0644"}, ApplyDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "644 5", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "hullo", nil },
			NewSFTPClient:     func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
				gotDest, gotData, gotMode = dest, string(data), mode
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotDest != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" || gotData != "hello" || gotMode != 0o644 {
			t.Fatalf("unexpected write payload: dest=%q data=%q mode=%#o", gotDest, gotData, gotMode)
		}
	})

	t.Run("skip write when destination already matches", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf", Mode: "0644"}, ApplyDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "644 5", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "hello", nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) {
				t.Fatalf("sftp client should not be created when destination already matches")
				return nil, nil
			},
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error {
				t.Fatalf("write should be skipped when destination already matches")
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
	})

	t.Run("default mode on parse failure", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		gotMode := os.FileMode(0)
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/tmp/example.conf", Mode: "bad"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, mode os.FileMode) error {
				gotMode = mode
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotMode != 0o600 {
			t.Fatalf("expected default mode 0600, got %#o", gotMode)
		}
	})
}

func TestPlan(t *testing.T) {
	t.Run("profile required", func(t *testing.T) {
		_, err := Plan(pluginapi.PlanContext{Runtime: templateRuntimeStub{}}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		_, err := Plan(pluginapi.PlanContext{Runtime: templateRuntimeStub{}, Profile: p}, &Spec{Src: "templates/missing.tmpl", Dest: "/etc/example.conf"})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("exists and matches", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Runtime: templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 5}, readContent: "hello"}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf", Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(res.Summary, "no rewrite required") {
			t.Fatalf("unexpected summary: %q", res.Summary)
		}
	})

	t.Run("missing and mismatched", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Runtime: templateRuntimeStub{statErr: errors.New("missing")}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/nftables.d/99-hardline-firewall.nft"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "does not exist") {
			t.Fatalf("expected missing destination detail, got %+v", res.Details)
		}
	})

	t.Run("read compare error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Runtime: templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o600, size: 4}, readErr: errors.New("boom")}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "cannot compare content") {
			t.Fatalf("expected compare error detail, got %+v", res.Details)
		}
	})

	t.Run("root stat error detail", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{
			Runtime: templateRuntimeHelperStub{runRootWithOutputErr: errors.New("boom")},
			Profile: p,
		}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "cannot stat destination") {
			t.Fatalf("expected stat error detail, got %+v", res.Details)
		}
	})
}

func TestStatTemplateDestination(t *testing.T) {
	t.Run("runtime required", func(t *testing.T) {
		if _, _, err := statTemplateDestination(nil, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "runtime is required") {
			t.Fatalf("expected runtime error, got %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		size, mode, err := statTemplateDestination(templateRuntimeHelperStub{runRootErr: errors.New("missing")}, "/etc/example.conf")
		if err != nil || size != -1 || mode != 0 {
			t.Fatalf("unexpected missing result size=%d mode=%#o err=%v", size, mode, err)
		}
	})

	t.Run("stat command error", func(t *testing.T) {
		if _, _, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutputErr: errors.New("boom")}, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected stat command error, got %v", err)
		}
	})

	t.Run("parse errors", func(t *testing.T) {
		for _, raw := range []string{"bad", "xyz 5", "644 bad", "644 5 extra"} {
			if _, _, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutput: raw}, "/etc/example.conf"); err == nil {
				t.Fatalf("expected parse error for %q", raw)
			}
		}
	})

	t.Run("success", func(t *testing.T) {
		size, mode, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutput: "640 1549"}, "/etc/example.conf")
		if err != nil || size != 1549 || mode.Perm() != 0o640 {
			t.Fatalf("unexpected success result size=%d mode=%#o err=%v", size, mode, err)
		}
	})
}

func TestCaptureRollback(t *testing.T) {
	t.Run("capture rollback", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, "t", nil, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "template spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}

		_, err = CaptureRollback(pluginapi.RollbackContext{}, "t", &Spec{Dest: "/tmp/nope.conf"}, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "outside /etc") {
			t.Fatalf("expected managed path error, got %v", err)
		}

		_, err = CaptureRollback(pluginapi.RollbackContext{}, "t", &Spec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}, RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", errors.New("stat boom") },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
		})
		if err == nil || !strings.Contains(err.Error(), "capture template snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}

		rec, err := CaptureRollback(pluginapi.RollbackContext{}, "t", &Spec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}, RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "644", nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "content", nil },
		})
		if err != nil {
			t.Fatalf("CaptureRollback failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 1 || rec.Objects[0].File == nil {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
	})
}

func mustLoadProfileForTemplateTests(t *testing.T, templates map[string]string) *profile.Profile {
	t.Helper()
	dir := t.TempDir()

	tplList := make([]string, 0, len(templates))
	for rel, content := range templates {
		tplList = append(tplList, rel)
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %q: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write template %q: %v", path, err)
		}
	}

	profileJSON := `{
  "id": "p",
  "display_name": "P",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": 1,
  "min_hardline": "1.0.0",
  "actions": [],
  "templates": ["` + strings.Join(tplList, `","`) + `"]
}`
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(profileJSON), 0o644); err != nil {
		t.Fatalf("write profile.json: %v", err)
	}

	p, err := profile.Load(dir)
	if err != nil {
		t.Fatalf("profile.Load failed: %v", err)
	}
	return p
}

type fakeFileInfo struct {
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return "x" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

type templateRuntimeStub struct {
	statInfo    os.FileInfo
	statErr     error
	readContent string
	readErr     error
}

func (s templateRuntimeStub) RunRoot(string) error {
	if s.statErr != nil {
		return s.statErr
	}
	if s.statInfo != nil {
		return nil
	}
	return errors.New("missing")
}

func (s templateRuntimeStub) RunRootWithOutput(string) (string, error) {
	if s.statErr != nil {
		return "", s.statErr
	}
	if s.statInfo != nil {
		return fmt.Sprintf("%o %d", s.statInfo.Mode().Perm(), s.statInfo.Size()), nil
	}
	return "", errors.New("missing")
}

func (s templateRuntimeStub) Stat(string) (os.FileInfo, error) {
	if s.statErr != nil {
		return nil, s.statErr
	}
	if s.statInfo != nil {
		return s.statInfo, nil
	}
	return nil, errors.New("missing")
}
func (s templateRuntimeStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}

type templateRuntimeHelperStub struct {
	runRootErr           error
	runRootWithOutput    string
	runRootWithOutputErr error
}

func (s templateRuntimeHelperStub) RunRoot(string) error { return s.runRootErr }

func (s templateRuntimeHelperStub) RunRootWithOutput(string) (string, error) {
	return s.runRootWithOutput, s.runRootWithOutputErr
}

func (templateRuntimeHelperStub) Stat(string) (os.FileInfo, error) { return nil, nil }

func (templateRuntimeHelperStub) ReadRootFile(string) (string, error) { return "", nil }
