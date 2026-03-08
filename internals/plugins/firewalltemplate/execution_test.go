package firewalltemplate

import (
	"errors"
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
	t.Run("unsupported backend", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "ok"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "ufw"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected backend error, got %v", err)
		}
	})

	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &profile.FirewallTemplateSpec{Backend: "nftables"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("template load error", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/other.tmpl": "ok"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "load nftables template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("parse and execute errors", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables", TemplateSrc: "templates/bad.tmpl"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "parse nftables template") {
			t.Fatalf("expected parse error, got %v", err)
		}

		p = mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{index .Missing 0}}"})
		err = Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables", TemplateSrc: "templates/bad.tmpl"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "execute nftables template") {
			t.Fatalf("expected execute error, got %v", err)
		}
	})

	t.Run("mkdir include sftp write errors", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "{{allow_rules}}"})

		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables"}, ApplyDeps{
			RunRoot: func(*ssh.Client, string) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("expected mkdir error, got %v", err)
		}

		checkCount := 0
		err = Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				if cmd == `grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf` {
					checkCount++
					return errors.New("missing")
				}
				if strings.Contains(cmd, ">> /etc/nftables.conf") {
					return errors.New("append failed")
				}
				return nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure error, got %v", err)
		}
		if checkCount != 1 {
			t.Fatalf("expected one include check, got %d", checkCount)
		}

		err = Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}

		err = Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{Backend: "nftables"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success renders rules and marks dirty", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "table inet filter {\n{{allow_rules}}\n}"})
		var gotDest, gotText, marked string
		err := Apply(pluginapi.ApplyContext{Profile: p}, &profile.FirewallTemplateSpec{
			Backend: "nftables",
			Allow: []profile.FirewallTemplateRule{
				{Port: 22, Proto: "tcp"},
			},
		}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
				gotDest, gotText = dest, string(data)
				if mode != 0o644 {
					t.Fatalf("unexpected mode %#o", mode)
				}
				return nil
			},
			MarkServiceDirty: func(unit string) { marked = unit },
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotDest != DefaultManagedDestination || !strings.Contains(gotText, "tcp dport 22 accept") {
			t.Fatalf("unexpected render: dest=%q text=%q", gotDest, gotText)
		}
		if marked != "nftables" {
			t.Fatalf("expected nftables dirty marker, got %q", marked)
		}
	})
}

func TestPlanManagedDestinationAndCapture(t *testing.T) {
	if got := ManagedDestination(nil); got != DefaultManagedDestination {
		t.Fatalf("unexpected nil destination: %q", got)
	}
	if got := ManagedDestination(&profile.FirewallTemplateSpec{}); got != DefaultManagedDestination {
		t.Fatalf("unexpected empty destination: %q", got)
	}
	if got := ManagedDestination(&profile.FirewallTemplateSpec{TemplateDest: "/etc/nftables.d/99-hardline-custom.nft"}); got != "/etc/nftables.d/99-hardline-custom.nft" {
		t.Fatalf("unexpected custom destination: %q", got)
	}

	res, err := Plan(pluginapi.PlanContext{Inspector: fwTemplateInspectorStub{}}, &profile.FirewallTemplateSpec{Backend: "ufw"})
	if err != nil || !strings.Contains(res.Summary, "unsupported backend") {
		t.Fatalf("expected unsupported backend summary, got res=%+v err=%v", res, err)
	}

	_, err = Plan(pluginapi.PlanContext{Inspector: fwTemplateInspectorStub{}}, &profile.FirewallTemplateSpec{Backend: "nftables"})
	if err == nil || !strings.Contains(err.Error(), "template_src is required") {
		t.Fatalf("expected template_src error, got %v", err)
	}

	_, err = Plan(pluginapi.PlanContext{Inspector: fwTemplateInspectorStub{}}, &profile.FirewallTemplateSpec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl"})
	if err == nil || !strings.Contains(err.Error(), "template_dest is required") {
		t.Fatalf("expected template_dest error, got %v", err)
	}

	res, err = Plan(pluginapi.PlanContext{Inspector: fwTemplateInspectorStub{statInfo: fakeFileInfo{mode: 0o644, size: 10}}}, &profile.FirewallTemplateSpec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl", TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"})
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if len(res.Details) == 0 || !strings.Contains(res.Summary, "best-effort") {
		t.Fatalf("unexpected plan result: %+v", res)
	}

	_, err = CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "ft", Type: "firewall_template"}, RollbackDeps{})
	if err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}

	_, err = CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "ft", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{TemplateDest: "/tmp/nope.nft"}}, RollbackDeps{})
	if err == nil || !strings.Contains(err.Error(), "outside /etc") {
		t.Fatalf("expected managed path error, got %v", err)
	}

	rec, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "ft", Type: "firewall_template", FirewallTemplate: &profile.FirewallTemplateSpec{TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"}}, RollbackDeps{
		RunRoot:           func(*ssh.Client, string) error { return nil },
		RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "644", nil },
		ReadRootFile:      func(*ssh.Client, string) (string, error) { return "abc", nil },
	})
	if err != nil {
		t.Fatalf("CaptureRollback failed: %v", err)
	}
	if rec.RollbackMode != "deterministic" || len(rec.Objects) != 1 || rec.Objects[0].File == nil {
		t.Fatalf("unexpected rollback record: %+v", rec)
	}
}

func mustLoadProfileForFirewallTemplateTests(t *testing.T, templates map[string]string) *profile.Profile {
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

type fwTemplateInspectorStub struct {
	statInfo os.FileInfo
}

func (s fwTemplateInspectorStub) PackageInstalled(string) bool                 { return false }
func (s fwTemplateInspectorStub) AptAutoremovePreview() ([]string, error)      { return nil, nil }
func (s fwTemplateInspectorStub) AptUpgradePreview() ([]string, error)         { return nil, nil }
func (s fwTemplateInspectorStub) AptInstallPreview([]string) ([]string, error) { return nil, nil }
func (s fwTemplateInspectorStub) Stat(string) (os.FileInfo, error) {
	if s.statInfo == nil {
		return nil, errors.New("missing")
	}
	return s.statInfo, nil
}
func (s fwTemplateInspectorStub) ReadRootFile(string) (string, error)             { return "", nil }
func (s fwTemplateInspectorStub) IsServiceEnabled(string) bool                    { return false }
func (s fwTemplateInspectorStub) IsServiceActive(string) bool                     { return false }
func (s fwTemplateInspectorStub) SSHIncludePresent() bool                         { return false }
func (s fwTemplateInspectorStub) SSHConfigTest() error                            { return nil }
func (s fwTemplateInspectorStub) FirewallIncludePresent() bool                    { return false }
func (s fwTemplateInspectorStub) FirewallConfigTest() error                       { return nil }
func (s fwTemplateInspectorStub) FirewallAllowedPorts() (map[string][]int, error) { return nil, nil }
func (s fwTemplateInspectorStub) FirewallPolicySummary() ([]string, error)        { return nil, nil }
func (s fwTemplateInspectorStub) FirewallOtherManagers() ([]string, error)        { return nil, nil }
func (s fwTemplateInspectorStub) FirewallOnDiskPolicySummary(string) ([]string, error) {
	return nil, nil
}
func (s fwTemplateInspectorStub) FirewallHasStatefulBaseline() (bool, error) { return false, nil }
func (s fwTemplateInspectorStub) FirewallHasDefaultDropInput() (bool, error) { return false, nil }
func (s fwTemplateInspectorStub) FirewallAllowedPortsDetailed() ([]pluginapi.FirewallRuleInfo, error) {
	return nil, nil
}
