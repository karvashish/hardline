package template

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

const (
	templateManagedConfigDest = "/etc/ssh/sshd_config.d/99-hardline-test.conf"
	templateManagedNftDest    = "/etc/nftables.d/99-hardline-firewall.nft"
)

func TestApply(t *testing.T) {
	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.Context{}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load template error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{}, Profile: p}, &Spec{Src: "templates/missing.tmpl", Dest: templateManagedConfigDest})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load template error, got %v", err)
		}
	})

	t.Run("host required", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err == nil || !strings.Contains(err.Error(), "host context is required") {
			t.Fatalf("expected host context error, got %v", err)
		}
	})

	t.Run("managed path required", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/shadow"})
		if err == nil || !strings.Contains(err.Error(), "template apply") {
			t.Fatalf("expected managed path apply error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{runRoot: func(string) error { return errors.New("boom") }}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err == nil || !strings.Contains(err.Error(), "mkdir -p") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{
			runRoot: func(cmd string) error {
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				return nil
			},
			writeRootFile: func(string, []byte, os.FileMode) error { return errors.New("boom") },
		}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err == nil || !strings.Contains(err.Error(), "write root file") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success explicit mode", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		var gotDest string
		var gotData string
		var gotMode os.FileMode
		err := Apply(pluginapi.Context{Host: templateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644 5", nil },
			readRootFile:      func(string) (string, error) { return "hullo", nil },
			writeRootFile: func(dest string, data []byte, mode os.FileMode) error {
				gotDest, gotData, gotMode = dest, string(data), mode
				return nil
			},
		}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotDest != templateManagedConfigDest || gotData != "hello" || gotMode != 0o644 {
			t.Fatalf("unexpected write payload: dest=%q data=%q mode=%#o", gotDest, gotData, gotMode)
		}
	})

	t.Run("skip write when destination already matches", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644 5", nil },
			readRootFile:      func(string) (string, error) { return "hello", nil },
			writeRootFile: func(string, []byte, os.FileMode) error {
				t.Fatalf("write should be skipped when destination already matches")
				return nil
			},
		}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
	})

	t.Run("error on invalid mode", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.Context{Host: templateExecHostStub{
			runRoot: func(cmd string) error {
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				return nil
			},
			writeRootFile: func(_ string, _ []byte, _ os.FileMode) error { return nil },
		}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "bad"})
		if err == nil {
			t.Fatal("expected error for invalid mode, got nil")
		}
		if !strings.Contains(err.Error(), "invalid file mode") {
			t.Fatalf("expected 'invalid mode' in error, got: %v", err)
		}
	})
}

func TestPlan(t *testing.T) {
	t.Run("profile required", func(t *testing.T) {
		_, err := Plan(pluginapi.Context{Host: templateRuntimeStub{}}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		_, err := Plan(pluginapi.Context{Host: templateRuntimeStub{}, Profile: p}, &Spec{Src: "templates/missing.tmpl", Dest: templateManagedConfigDest})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("managed path required", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		_, err := Plan(pluginapi.Context{Host: templateRuntimeStub{}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: "/etc/sudoers"})
		if err == nil || !strings.Contains(err.Error(), "template plan") {
			t.Fatalf("expected managed path plan error, got %v", err)
		}
	})

	t.Run("exists and matches", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.Context{Host: templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 5}, readContent: "hello"}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange {
			t.Fatalf("expected matching template to be aligned, got WillChange=true")
		}
		if !strings.Contains(res.Summary, "no rewrite required") {
			t.Fatalf("unexpected summary: %q", res.Summary)
		}
		if len(res.Diff) != 0 {
			t.Fatalf("expected aligned template to have no diff, got %+v", res.Diff)
		}
	})

	t.Run("missing and mismatched", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.Context{Host: templateRuntimeStub{statErr: errors.New("missing")}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedNftDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected missing destination to require change, got WillChange=false")
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "does not exist") {
			t.Fatalf("expected missing destination detail, got %+v", res.Details)
		}
		joinedDiff := strings.Join(res.Diff, "\n")
		if !strings.Contains(joinedDiff, `file "/etc/nftables.d/99-hardline-firewall.nft": absent -> present`) || !strings.Contains(joinedDiff, "+hello") {
			t.Fatalf("expected create diff, got %+v", res.Diff)
		}
	})

	t.Run("content and mode drift", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello\nworld\n"})
		res, err := Plan(pluginapi.Context{
			Host:    templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o600, size: 12}, readContent: "hullo\nworld\n"},
			Profile: p,
		}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		joinedDiff := strings.Join(res.Diff, "\n")
		for _, want := range []string{
			`file mode "/etc/ssh/sshd_config.d/99-hardline-test.conf": 0600 -> 0644`,
			`--- current /etc/ssh/sshd_config.d/99-hardline-test.conf`,
			`+++ desired /etc/ssh/sshd_config.d/99-hardline-test.conf`,
			`-hullo`,
			`+hello`,
		} {
			if !strings.Contains(joinedDiff, want) {
				t.Fatalf("expected diff %q, got %s", want, joinedDiff)
			}
		}
	})

	t.Run("read compare error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.Context{Host: templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o600, size: 4}, readErr: errors.New("boom")}, Profile: p}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "cannot compare content") {
			t.Fatalf("expected compare error detail, got %+v", res.Details)
		}
	})

	t.Run("root stat error detail", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.Context{
			Host:    templateRuntimeHelperStub{runRootWithOutputErr: errors.New("boom")},
			Profile: p,
		}, &Spec{Src: "templates/t.tmpl", Dest: templateManagedConfigDest, Mode: "0644"})
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
		if _, _, err := statTemplateDestination(nil, templateManagedConfigDest); err == nil || !strings.Contains(err.Error(), "runtime is required") {
			t.Fatalf("expected runtime error, got %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		size, mode, err := statTemplateDestination(templateRuntimeHelperStub{runRootErr: errors.New("missing")}, templateManagedConfigDest)
		if err != nil || size != -1 || mode != 0 {
			t.Fatalf("unexpected missing result size=%d mode=%#o err=%v", size, mode, err)
		}
	})

	t.Run("stat command error", func(t *testing.T) {
		if _, _, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutputErr: errors.New("boom")}, templateManagedConfigDest); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected stat command error, got %v", err)
		}
	})

	t.Run("parse errors", func(t *testing.T) {
		for _, raw := range []string{"bad", "xyz 5", "644 bad", "644 5 extra"} {
			if _, _, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutput: raw}, templateManagedConfigDest); err == nil {
				t.Fatalf("expected parse error for %q", raw)
			}
		}
	})

	t.Run("success", func(t *testing.T) {
		size, mode, err := statTemplateDestination(templateRuntimeHelperStub{runRootWithOutput: "640 1549"}, templateManagedConfigDest)
		if err != nil || size != 1549 || mode.Perm() != 0o640 {
			t.Fatalf("unexpected success result size=%d mode=%#o err=%v", size, mode, err)
		}
	})
}

func TestCapture(t *testing.T) {
	t.Run("capture rollback", func(t *testing.T) {
		_, err := Capture(pluginapi.Context{}, "t", nil)
		if err == nil || !strings.Contains(err.Error(), "template spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}

		_, err = Capture(pluginapi.Context{Host: templateExecHostStub{}}, "t", &Spec{Dest: "/tmp/nope.conf"})
		if err == nil || !strings.Contains(err.Error(), "outside /etc") {
			t.Fatalf("expected managed path error, got %v", err)
		}

		_, err = Capture(pluginapi.Context{Host: templateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "", errors.New("stat boom") },
			readRootFile:      func(string) (string, error) { return "", nil },
		}}, "t", &Spec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"})
		if err == nil || !strings.Contains(err.Error(), "capture template snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}

		rec, err := Capture(pluginapi.Context{Host: templateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "regular file|644|root|root|7", nil },
			readRootFile:      func(string) (string, error) { return "content", nil },
		}}, "t", &Spec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 1 || rec.Objects[0].File == nil {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
	})
}

func mustLoadProfileForTemplateTests(t *testing.T, templates map[string]string) *profile.Profile {
	t.Helper()

	files := make(map[string][]byte, len(templates)+1)
	tplList := make([]string, 0, len(templates))
	for rel, content := range templates {
		tplList = append(tplList, rel)
		files[rel] = []byte(content)
	}
	sort.Strings(tplList)

	files["profile.json"] = []byte(`{
  "id": "p",
  "display_name": "P",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": 1,
  "min_hardline": "1.0.0",
  "actions": [],
  "templates": ["` + strings.Join(tplList, `","`) + `"],
  "allowed_overrides": []
}`)

	p, err := profile.LoadFromBundle(t.TempDir(), files)
	if err != nil {
		t.Fatalf("profile.LoadFromBundle failed: %v", err)
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

func (s templateRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if s.statErr != nil {
		return "", s.statErr
	}
	if s.statInfo == nil {
		return "", errors.New("missing")
	}
	if strings.Contains(cmd, "%F|") {
		return fmt.Sprintf("regular file|%o|root|root|%d", s.statInfo.Mode().Perm(), s.statInfo.Size()), nil
	}
	return fmt.Sprintf("%o %d", s.statInfo.Mode().Perm(), s.statInfo.Size()), nil
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

func (templateRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func (s templateRuntimeStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
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

func (templateRuntimeHelperStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func (s templateRuntimeHelperStub) RunRootWithTimeout(string, time.Duration) (string, error) {
	return s.runRootWithOutput, s.runRootWithOutputErr
}

type templateExecHostStub struct {
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s templateExecHostStub) RunRoot(cmd string) error {
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s templateExecHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput == nil {
		return "", nil
	}
	return s.runRootWithOutput(cmd)
}

func (templateExecHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("missing") }

func (s templateExecHostStub) ReadRootFile(path string) (string, error) {
	if s.readRootFile == nil {
		return "", nil
	}
	return s.readRootFile(path)
}

func (s templateExecHostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile == nil {
		return nil
	}
	return s.writeRootFile(path, data, mode)
}

func (s templateExecHostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}
