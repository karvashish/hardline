package main

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
	t.Run("unsupported backend", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "ok"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "ufw"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected backend error, got %v", err)
		}
	})

	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{Backend: "nftables"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("template load error", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/other.tmpl": "ok"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "load nftables template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("parse and execute errors", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{"})
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables", TemplateSrc: "templates/bad.tmpl"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "parse nftables template") {
			t.Fatalf("expected parse error, got %v", err)
		}

		p = mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{index .Missing 0}}"})
		err = Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables", TemplateSrc: "templates/bad.tmpl"}, ApplyDeps{
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

		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables"}, ApplyDeps{
			RunRoot: func(*ssh.Client, string) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("expected mkdir error, got %v", err)
		}

		checkCount := 0
		err = Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables"}, ApplyDeps{
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

		err = Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}

		err = Apply(pluginapi.ApplyContext{Profile: p}, &Spec{Backend: "nftables"}, ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success renders rules", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "table inet filter {\n{{allow_rules}}\n}"})
		var gotDest, gotText string
		wantText := "table inet filter {\n# hardline: allow rules from profile\n    tcp dport 22 accept\n\n}"
		err := Apply(pluginapi.ApplyContext{Profile: p}, &Spec{
			Backend: "nftables",
			Allow: []AllowRule{
				{Port: 22, Proto: "tcp"},
			},
		}, ApplyDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return fmt.Sprintf("644 %d", len(wantText)), nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return wantText, nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) {
				t.Fatalf("sftp client should not be created when firewall template output already matches")
				return nil, nil
			},
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error {
				t.Fatalf("write should be skipped when firewall template output already matches")
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		err = Apply(pluginapi.ApplyContext{Profile: p}, &Spec{
			Backend: "nftables",
			Allow: []AllowRule{
				{Port: 22, Proto: "tcp"},
			},
		}, ApplyDeps{
			RunRoot:           func(*ssh.Client, string) error { return nil },
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return fmt.Sprintf("644 %d", len(wantText)), nil },
			ReadRootFile:      func(*ssh.Client, string) (string, error) { return wantText + "\n# drift", nil },
			NewSFTPClient:     func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
				gotDest, gotText = dest, string(data)
				if mode != 0o644 {
					t.Fatalf("unexpected mode %#o", mode)
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if gotDest != DefaultManagedDestination || !strings.Contains(gotText, "tcp dport 22 accept") {
			t.Fatalf("unexpected render: dest=%q text=%q", gotDest, gotText)
		}
	})
}

func TestPlanManagedDestinationAndCapture(t *testing.T) {
	if got := ManagedDestination(nil); got != DefaultManagedDestination {
		t.Fatalf("unexpected nil destination: %q", got)
	}
	if got := ManagedDestination(&Spec{}); got != DefaultManagedDestination {
		t.Fatalf("unexpected empty destination: %q", got)
	}
	if got := ManagedDestination(&Spec{TemplateDest: "/etc/nftables.d/99-hardline-custom.nft"}); got != "/etc/nftables.d/99-hardline-custom.nft" {
		t.Fatalf("unexpected custom destination: %q", got)
	}

	res, err := Plan(pluginapi.PlanContext{Runtime: fwTemplateRuntimeStub{}}, &Spec{Backend: "ufw"})
	if err != nil || !strings.Contains(res.Summary, "unsupported backend") {
		t.Fatalf("expected unsupported backend summary, got res=%+v err=%v", res, err)
	}

	res, err = Plan(pluginapi.PlanContext{Runtime: fwTemplateRuntimeStub{}}, &Spec{Backend: "nftables"})
	if err != nil {
		t.Fatalf("expected defaulted template plan success, got %v", err)
	}
	if !strings.Contains(res.Summary, "templates/nftables_base.tmpl") || !strings.Contains(res.Summary, DefaultManagedDestination) {
		t.Fatalf("expected plan summary to use defaults, got %+v", res)
	}

	res, err = Plan(pluginapi.PlanContext{Runtime: fwTemplateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 10}}}, &Spec{Backend: "nftables", TemplateSrc: "templates/nftables_base.tmpl", TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"})
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if len(res.Details) == 0 || !strings.Contains(res.Summary, "best-effort") {
		t.Fatalf("unexpected plan result: %+v", res)
	}

	_, err = CaptureRollback(pluginapi.RollbackContext{}, "ft", nil, RollbackDeps{})
	if err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}

	_, err = CaptureRollback(pluginapi.RollbackContext{}, "ft", &Spec{TemplateDest: "/tmp/nope.nft"}, RollbackDeps{})
	if err == nil || !strings.Contains(err.Error(), "outside /etc") {
		t.Fatalf("expected managed path error, got %v", err)
	}

	rec, err := CaptureRollback(pluginapi.RollbackContext{}, "ft", &Spec{TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"}, RollbackDeps{
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

func TestDestinationHelpersAndPlugin(t *testing.T) {
	t.Run("stat destination helper", func(t *testing.T) {
		if _, _, err := statFirewallTemplateDestination(nil, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "runtime is required") {
			t.Fatalf("expected runtime error, got %v", err)
		}

		size, mode, err := statFirewallTemplateDestination(fwTemplateHelperRuntimeStub{runRootErr: errors.New("missing")}, "/etc/example.conf")
		if err != nil || size != -1 || mode != 0 {
			t.Fatalf("unexpected missing result size=%d mode=%#o err=%v", size, mode, err)
		}

		if _, _, err := statFirewallTemplateDestination(fwTemplateHelperRuntimeStub{runRootWithOutputErr: errors.New("boom")}, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected stat command error, got %v", err)
		}

		for _, raw := range []string{"bad", "xyz 5", "644 bad", "644 5 extra"} {
			if _, _, err := statFirewallTemplateDestination(fwTemplateHelperRuntimeStub{runRootWithOutput: raw}, "/etc/example.conf"); err == nil {
				t.Fatalf("expected parse error for %q", raw)
			}
		}

		size, mode, err = statFirewallTemplateDestination(fwTemplateHelperRuntimeStub{runRootWithOutput: "644 10"}, "/etc/example.conf")
		if err != nil || size != 10 || mode.Perm() != 0o644 {
			t.Fatalf("unexpected success result size=%d mode=%#o err=%v", size, mode, err)
		}
	})

	t.Run("destination matches helper", func(t *testing.T) {
		matches, err := firewallTemplateDestinationMatches(
			fwTemplateHelperRuntimeStub{runRootWithOutput: "644 5", readContent: "hello"},
			"/etc/example.conf",
			"hello",
			0o644,
		)
		if err != nil || !matches {
			t.Fatalf("expected matching destination, got matches=%v err=%v", matches, err)
		}

		matches, err = firewallTemplateDestinationMatches(
			fwTemplateHelperRuntimeStub{runRootWithOutput: "600 5", readContent: "hello"},
			"/etc/example.conf",
			"hello",
			0o644,
		)
		if err != nil || matches {
			t.Fatalf("expected mode mismatch to skip compare result, got matches=%v err=%v", matches, err)
		}

		matches, err = firewallTemplateDestinationMatches(
			fwTemplateHelperRuntimeStub{runRootWithOutput: "644 5", readErr: errors.New("boom")},
			"/etc/example.conf",
			"hello",
			0o644,
		)
		if err == nil || !strings.Contains(err.Error(), "boom") || matches {
			t.Fatalf("expected read error, got matches=%v err=%v", matches, err)
		}
	})

	t.Run("plugin decode errors", func(t *testing.T) {
		plugin := Plugin(ApplyDeps{
			RunRoot:       func(*ssh.Client, string) error { return nil },
			NewSFTPClient: func(*ssh.Client) (*sftp.Client, error) { return nil, nil },
			WriteRootFile: func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error { return nil },
		}, RollbackDeps{})
		step := profile.Step{
			ID:     "bad-firewall-template",
			Plugin: "firewall_template",
			Config: map[string]any{"backend": 1},
		}

		if err := plugin.Apply(pluginapi.ApplyContext{}, step); err == nil {
			t.Fatalf("expected plugin apply decode error")
		}
		if _, err := plugin.Plan(pluginapi.PlanContext{Runtime: fwTemplateRuntimeStub{}}, step); err == nil {
			t.Fatalf("expected plugin plan decode error")
		}
		if _, err := plugin.Rollback(pluginapi.RollbackContext{}, step); err == nil {
			t.Fatalf("expected plugin rollback decode error")
		}
	})
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

type fwTemplateRuntimeStub struct {
	statInfo os.FileInfo
}

func (fwTemplateRuntimeStub) RunRoot(string) error { return nil }

func (fwTemplateRuntimeStub) RunRootWithOutput(string) (string, error) { return "", nil }

func (s fwTemplateRuntimeStub) Stat(string) (os.FileInfo, error) {
	if s.statInfo == nil {
		return nil, errors.New("missing")
	}
	return s.statInfo, nil
}
func (fwTemplateRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }

type fwTemplateHelperRuntimeStub struct {
	runRootErr           error
	runRootWithOutput    string
	runRootWithOutputErr error
	readContent          string
	readErr              error
}

func (s fwTemplateHelperRuntimeStub) RunRoot(string) error { return s.runRootErr }

func (s fwTemplateHelperRuntimeStub) RunRootWithOutput(string) (string, error) {
	return s.runRootWithOutput, s.runRootWithOutputErr
}

func (s fwTemplateHelperRuntimeStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}
