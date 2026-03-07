package template

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestApply(t *testing.T) {
	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load template error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/missing.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load template error, got %v", err)
		}
	})

	t.Run("new sftp error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
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
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success explicit mode and dirty marker", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		var gotDest string
		var gotData string
		var gotMode os.FileMode
		var marked string
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf", Mode: "0644"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
				gotDest, gotData, gotMode = dest, string(data), mode
				return nil
			},
			MarkServiceDirty: func(unit string) { marked = unit },
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotDest != "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" || gotData != "hello" || gotMode != 0o644 {
			t.Fatalf("unexpected write payload: dest=%q data=%q mode=%#o", gotDest, gotData, gotMode)
		}
		if marked != "ssh" {
			t.Fatalf("expected ssh dirty marker, got %q", marked)
		}
	})

	t.Run("default mode on parse failure", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		gotMode := os.FileMode(0)
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/tmp/example.conf", Mode: "bad"}, ApplyDeps{
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
		_, err := Plan(pluginapi.PlanContext{Inspector: templateInspectorStub{}}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("load error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		_, err := Plan(pluginapi.PlanContext{Inspector: templateInspectorStub{}, Profile: p}, &profile.TemplateSpec{Src: "templates/missing.tmpl", Dest: "/etc/example.conf"})
		if err == nil || !strings.Contains(err.Error(), "load template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("exists and matches", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Inspector: templateInspectorStub{statInfo: fakeFileInfo{mode: 0o644, size: 5}, readContent: "hello", sshInclude: true, sshTestErr: nil}, Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf", Mode: "0644"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(res.Summary, "no rewrite required") {
			t.Fatalf("unexpected summary: %q", res.Summary)
		}
	})

	t.Run("missing and mismatched", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Inspector: templateInspectorStub{statErr: errors.New("missing")}, Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/nftables.d/99-hardline-firewall.nft"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "does not exist") {
			t.Fatalf("expected missing destination detail, got %+v", res.Details)
		}
	})

	t.Run("read compare error", func(t *testing.T) {
		p := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
		res, err := Plan(pluginapi.PlanContext{Inspector: templateInspectorStub{statInfo: fakeFileInfo{mode: 0o600, size: 4}, readErr: errors.New("boom")}, Profile: p}, &profile.TemplateSpec{Src: "templates/t.tmpl", Dest: "/etc/example.conf"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !strings.Contains(strings.Join(res.Details, "\n"), "cannot compare content") {
			t.Fatalf("expected compare error detail, got %+v", res.Details)
		}
	})
}

func TestValidateAndCapture(t *testing.T) {
	t.Run("validate apply success and errors", func(t *testing.T) {
		if err := ValidateApply(pluginapi.ApplyContext{}, func(*ssh.Client, string) error { return nil }); err != nil {
			t.Fatalf("ValidateApply failed: %v", err)
		}
		err := ValidateApply(pluginapi.ApplyContext{}, func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "grep -q") {
				return errors.New("missing")
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "missing Include") {
			t.Fatalf("expected include error, got %v", err)
		}
		err = ValidateApply(pluginapi.ApplyContext{}, func(_ *ssh.Client, cmd string) error {
			if strings.Contains(cmd, "sshd -t") {
				return errors.New("bad")
			}
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "config test failed") {
			t.Fatalf("expected config test error, got %v", err)
		}
	})

	t.Run("validate plan", func(t *testing.T) {
		res, err := ValidatePlan(pluginapi.PlanContext{Inspector: templateInspectorStub{sshInclude: true}})
		if err != nil {
			t.Fatalf("ValidatePlan failed: %v", err)
		}
		if !strings.Contains(res.Summary, "validate sshd") || len(res.Details) == 0 {
			t.Fatalf("unexpected validate plan result: %+v", res)
		}

		res, err = ValidatePlan(pluginapi.PlanContext{Inspector: templateInspectorStub{sshInclude: false, sshTestErr: errors.New("bad")}})
		if err != nil {
			t.Fatalf("ValidatePlan failed: %v", err)
		}
		joined := strings.Join(res.Details, "\n")
		if !strings.Contains(joined, "missing") || !strings.Contains(joined, "reports errors") {
			t.Fatalf("unexpected validate plan details: %s", joined)
		}
	})

	t.Run("capture rollback", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "t", Type: "template"}, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "template spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}

		_, err = CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "t", Type: "template", Template: &profile.TemplateSpec{Dest: "/tmp/nope.conf"}}, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "outside /etc") {
			t.Fatalf("expected managed path error, got %v", err)
		}

		_, err = CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "t", Type: "template", Template: &profile.TemplateSpec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}}, RollbackDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", errors.New("stat boom") },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return "", nil },
		})
		if err == nil || !strings.Contains(err.Error(), "capture template snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}

		rec, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "t", Type: "template", Template: &profile.TemplateSpec{Dest: "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"}}, RollbackDeps{
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

func TestServiceForManagedPath(t *testing.T) {
	cases := map[string]string{
		"/etc/ssh/sshd_config.d/99-hardline.conf":       "ssh",
		"/etc/sysctl.d/99-hardline.conf":                "systemd-sysctl",
		"/etc/fail2ban/jail.d/99-hardline.conf":         "fail2ban",
		"/etc/audit/rules.d/99-hardline.rules":          "auditd",
		"/etc/systemd/journald.conf.d/99-hardline.conf": "systemd-journald",
		"/etc/nftables.d/99-hardline-firewall.nft":      "nftables",
		"/etc/custom/other.conf":                        "",
	}
	for in, want := range cases {
		if got := serviceForManagedPath(in); got != want {
			t.Fatalf("unexpected service mapping for %q: got %q want %q", in, got, want)
		}
	}
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

type templateInspectorStub struct {
	statInfo    os.FileInfo
	statErr     error
	readContent string
	readErr     error
	sshInclude  bool
	sshTestErr  error
}

func (s templateInspectorStub) PackageInstalled(string) bool                 { return false }
func (s templateInspectorStub) AptAutoremovePreview() ([]string, error)      { return nil, nil }
func (s templateInspectorStub) AptUpgradePreview() ([]string, error)         { return nil, nil }
func (s templateInspectorStub) AptInstallPreview([]string) ([]string, error) { return nil, nil }
func (s templateInspectorStub) Stat(string) (os.FileInfo, error) {
	if s.statErr != nil {
		return nil, s.statErr
	}
	if s.statInfo != nil {
		return s.statInfo, nil
	}
	return nil, errors.New("missing")
}
func (s templateInspectorStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}
func (s templateInspectorStub) IsServiceEnabled(string) bool                         { return false }
func (s templateInspectorStub) IsServiceActive(string) bool                          { return false }
func (s templateInspectorStub) SSHIncludePresent() bool                              { return s.sshInclude }
func (s templateInspectorStub) SSHConfigTest() error                                 { return s.sshTestErr }
func (s templateInspectorStub) FirewallIncludePresent() bool                         { return false }
func (s templateInspectorStub) FirewallConfigTest() error                            { return nil }
func (s templateInspectorStub) FirewallAllowedPorts() (map[string][]int, error)      { return nil, nil }
func (s templateInspectorStub) FirewallPolicySummary() ([]string, error)             { return nil, nil }
func (s templateInspectorStub) FirewallOtherManagers() ([]string, error)             { return nil, nil }
func (s templateInspectorStub) FirewallOnDiskPolicySummary(string) ([]string, error) { return nil, nil }
func (s templateInspectorStub) FirewallHasStatefulBaseline() (bool, error)           { return false, nil }
func (s templateInspectorStub) FirewallHasDefaultDropInput() (bool, error)           { return false, nil }
func (s templateInspectorStub) FirewallAllowedPortsDetailed() ([]inspector.FirewallRuleInfo, error) {
	return nil, nil
}
