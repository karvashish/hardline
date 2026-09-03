package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestApply(t *testing.T) {
	t.Run("unsupported backend", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "ok"})
		err := Apply(pluginapi.Context{Host: fwTemplateExecHostStub{}, Profile: p}, &Spec{Backend: "ufw"})
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected backend error, got %v", err)
		}
	})

	t.Run("profile required", func(t *testing.T) {
		err := Apply(pluginapi.Context{}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
		if err == nil || !strings.Contains(err.Error(), "profile context is required") {
			t.Fatalf("expected profile context error, got %v", err)
		}
	})

	t.Run("template load error", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/other.tmpl": "ok"})
		err := Apply(pluginapi.Context{Host: fwTemplateExecHostStub{}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, TemplateSrc: "templates/nftables_base.tmpl"})
		if err == nil || !strings.Contains(err.Error(), "load nftables template") {
			t.Fatalf("expected load error, got %v", err)
		}
	})

	t.Run("parse and execute errors", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{"})
		err := Apply(pluginapi.Context{Host: fwTemplateExecHostStub{}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, TemplateSrc: "templates/bad.tmpl"})
		if err == nil || !strings.Contains(err.Error(), "parse nftables template") {
			t.Fatalf("expected parse error, got %v", err)
		}

		p = mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/bad.tmpl": "{{index .Missing 0}}"})
		err = Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot:       func(string) error { return nil },
			writeRootFile: func(string, []byte, os.FileMode) error { return nil },
		}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, TemplateSrc: "templates/bad.tmpl"})
		if err == nil || !strings.Contains(err.Error(), "execute nftables template") {
			t.Fatalf("expected execute error, got %v", err)
		}
	})

	t.Run("mkdir include sftp write errors", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "{{allow_rules}}"})

		err := Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot: func(string) error { return errors.New("boom") },
		}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
		if err == nil || !strings.Contains(err.Error(), "mkdir") {
			t.Fatalf("expected mkdir error, got %v", err)
		}

		checkCount := 0
		err = Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot: func(cmd string) error {
				if cmd == includeCheckCmd(MainConfigDebian, DefaultManagedDestination) {
					checkCount++
					return errors.New("missing")
				}
				if strings.Contains(cmd, ">> '/etc/nftables.conf'") {
					return errors.New("append failed")
				}
				return nil
			},
		}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure error, got %v", err)
		}
		if checkCount != 1 {
			t.Fatalf("expected one include check, got %d", checkCount)
		}

		err = Apply(pluginapi.Context{Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
		if err == nil || !strings.Contains(err.Error(), "host context is required") {
			t.Fatalf("expected host error, got %v", err)
		}

		err = Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot: func(cmd string) error {
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				return nil
			},
			writeRootFile: func(string, []byte, os.FileMode) error { return errors.New("boom") },
		}, Profile: p}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
		if err == nil || !strings.Contains(err.Error(), "write root file") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success renders rules", func(t *testing.T) {
		p := mustLoadProfileForFirewallTemplateTests(t, map[string]string{"templates/nftables_base.tmpl": "table inet filter {\n{{allow_rules}}\n}"})
		var gotDest, gotText string
		wantText := "table inet filter {\n# hardline: allow rules from profile\n    tcp dport 22 accept\n\n}"
		err := Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return fmt.Sprintf("644 %d", len(wantText)), nil },
			readRootFile:      func(string) (string, error) { return wantText, nil },
			writeRootFile: func(string, []byte, os.FileMode) error {
				t.Fatalf("write should be skipped when firewall template output already matches")
				return nil
			},
		}, Profile: p}, &Spec{
			Backend:    "nftables",
			MainConfig: MainConfigDebian,
			Allow: []AllowRule{
				{Port: 22, Proto: "tcp"},
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		err = Apply(pluginapi.Context{Host: fwTemplateExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return fmt.Sprintf("644 %d", len(wantText)), nil },
			readRootFile:      func(string) (string, error) { return wantText + "\n# drift", nil },
			writeRootFile: func(dest string, data []byte, mode os.FileMode) error {
				gotDest, gotText = dest, string(data)
				if mode != 0o644 {
					t.Fatalf("unexpected mode %#o", mode)
				}
				return nil
			},
		}, Profile: p}, &Spec{
			Backend:    "nftables",
			MainConfig: MainConfigDebian,
			Allow: []AllowRule{
				{Port: 22, Proto: "tcp"},
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

	res, err := Plan(pluginapi.Context{Host: fwTemplateRuntimeStub{}}, &Spec{Backend: "ufw"})
	if err != nil || !strings.Contains(res.Summary, "unsupported backend") {
		t.Fatalf("expected unsupported backend summary, got res=%+v err=%v", res, err)
	}

	res, err = Plan(pluginapi.Context{Host: fwTemplateRuntimeStub{}}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian})
	if err != nil {
		t.Fatalf("expected defaulted template plan success, got %v", err)
	}
	if !strings.Contains(res.Summary, "templates/nftables_base.tmpl") || !strings.Contains(res.Summary, DefaultManagedDestination) {
		t.Fatalf("expected plan summary to use defaults, got %+v", res)
	}

	res, err = Plan(pluginapi.Context{Host: fwTemplateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 10}}}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, TemplateSrc: "templates/nftables_base.tmpl", TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"})
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if len(res.Details) == 0 || !strings.Contains(res.Summary, "firewall_template step") {
		t.Fatalf("unexpected plan result: %+v", res)
	}
	if len(res.Highlights) != 0 {
		t.Fatalf("expected no highlights for normal plan, got %+v", res.Highlights)
	}
	joinedDetails := strings.Join(res.Details, "\n")
	if !strings.Contains(joinedDetails, "live nftables ruleset may differ") {
		t.Fatalf("expected live ruleset note in details, got %+v", res.Details)
	}

	_, err = Capture(pluginapi.Context{}, "ft", nil)
	if err == nil || !strings.Contains(err.Error(), "firewall_template spec missing") {
		t.Fatalf("expected missing spec error, got %v", err)
	}

	_, err = Capture(pluginapi.Context{Host: fwTemplateExecHostStub{}}, "ft", &Spec{TemplateDest: "/tmp/nope.nft"})
	if err == nil || !strings.Contains(err.Error(), "outside /etc") {
		t.Fatalf("expected managed path error, got %v", err)
	}

	host := fwTemplateExecHostStub{
		runRoot:           func(string) error { return nil },
		runRootWithOutput: func(string) (string, error) { return "HL-STAT:regular file|644|root|root|5\nHL-RC:0\n", nil },
		readRootFile:      func(string) (string, error) { return "abc", nil },
	}

	_, err = Capture(pluginapi.Context{Host: host}, "ft",
		&Spec{TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft"})
	if err == nil || !strings.Contains(err.Error(), "unsupported main_config") {
		t.Fatalf("expected an unsupported main_config error, got %v", err)
	}

	rec, err := Capture(pluginapi.Context{Host: host}, "ft", &Spec{
		TemplateDest: "/etc/nftables.d/99-hardline-firewall.nft",
		MainConfig:   MainConfigRHEL,
	})
	if err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if rec.RollbackMode != "deterministic" || len(rec.Objects) != 2 {
		t.Fatalf("unexpected rollback record: %+v", rec)
	}
	if rec.Objects[0].File == nil || rec.Objects[0].File.Path != MainConfigRHEL {
		t.Fatalf("expected the main config first, got %+v", rec.Objects[0].File)
	}
	if rec.Objects[1].File == nil || rec.Objects[1].File.Path != "/etc/nftables.d/99-hardline-firewall.nft" {
		t.Fatalf("expected the managed destination second, got %+v", rec.Objects[1].File)
	}
}

func TestRollbackRestoresTheMainConfig(t *testing.T) {
	t.Run("restores prior content byte-for-byte", func(t *testing.T) {
		var wrotePath string
		var wrote []byte
		host := fwTemplateExecHostStub{
			writeRootFile: func(path string, data []byte, _ os.FileMode) error {
				wrotePath, wrote = path, data
				return nil
			},
		}
		snap := pluginapi.FileSnapshot{
			Path:       MainConfigDebian,
			Existed:    true,
			Mode:       "644",
			ContentB64: base64.StdEncoding.EncodeToString([]byte("flush ruleset\n")),
		}
		if err := restoreMainConfig(host, snap); err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if wrotePath != MainConfigDebian || string(wrote) != "flush ruleset\n" {
			t.Fatalf("restored %q with %q", wrotePath, wrote)
		}
	})

	t.Run("deletes a file that did not exist before apply", func(t *testing.T) {
		var cmd string
		host := fwTemplateExecHostStub{runRoot: func(c string) error {
			cmd = c
			return nil
		}}
		err := restoreMainConfig(host, pluginapi.FileSnapshot{Path: MainConfigRHEL, Existed: false})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(cmd, "rm -f '/etc/sysconfig/nftables.conf'") {
			t.Fatalf("got %q", cmd)
		}
	})

	t.Run("refuses a path that is not a main config", func(t *testing.T) {
		err := restoreMainConfig(fwTemplateExecHostStub{}, pluginapi.FileSnapshot{Path: "/etc/passwd", Existed: true})
		if err == nil || !strings.Contains(err.Error(), "unexpected main config path") {
			t.Fatalf("a tampered journal must not name another path, got %v", err)
		}
	})

	t.Run("host is required", func(t *testing.T) {
		if err := restoreMainConfig(nil, pluginapi.FileSnapshot{Path: MainConfigDebian}); err == nil {
			t.Fatal("expected a host-required error")
		}
	})

	t.Run("undecodable content surfaces", func(t *testing.T) {
		snap := pluginapi.FileSnapshot{Path: MainConfigDebian, Existed: true, ContentB64: "!!!not base64!!!"}
		if err := restoreMainConfig(fwTemplateExecHostStub{}, snap); err == nil {
			t.Fatal("expected a decode error")
		}
	})

	t.Run("the plugin routes the main config to this restore", func(t *testing.T) {
		var wrotePath string
		host := fwTemplateExecHostStub{
			writeRootFile: func(path string, _ []byte, _ os.FileMode) error {
				wrotePath = path
				return nil
			},
		}
		snap := pluginapi.FileSnapshot{Path: MainConfigDebian, Existed: true, Mode: "644"}
		err := Plugin().Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap})
		if err != nil {
			t.Fatalf("rollback failed: %v", err)
		}
		if wrotePath != MainConfigDebian {
			t.Fatalf("main config was not restored, wrote %q", wrotePath)
		}
	})
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
		plugin := Plugin()
		step := profile.Step{
			ID:     "bad-firewall-template",
			Plugin: "firewall_template",
			Config: map[string]any{"backend": 1},
		}

		if err := plugin.Apply(pluginapi.Context{}, step); err == nil {
			t.Fatalf("expected plugin apply decode error")
		}
		if _, err := plugin.Plan(pluginapi.Context{Host: fwTemplateRuntimeStub{}}, step); err == nil {
			t.Fatalf("expected plugin plan decode error")
		}
		if _, err := plugin.Capture(pluginapi.Context{}, step); err == nil {
			t.Fatalf("expected plugin rollback decode error")
		}
	})
}

func mustLoadProfileForFirewallTemplateTests(t *testing.T, templates map[string]string) *profile.Profile {
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

type fwTemplateRuntimeStub struct {
	statInfo os.FileInfo
}

func (fwTemplateRuntimeStub) RunRoot(string) error { return nil }

func (s fwTemplateRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if strings.Contains(cmd, "%F|") {
		if s.statInfo == nil {
			return "stat: cannot stat: No such file or directory\nHL-RC:1\n", nil
		}
		return fmt.Sprintf("HL-STAT:regular file|%o|root|root|%d\nHL-RC:0\n", s.statInfo.Mode().Perm(), s.statInfo.Size()), nil
	}
	return "", nil
}

func (fwTemplateRuntimeStub) RunRootWithTimeout(string, time.Duration) (string, error) {
	return "", nil
}

func (s fwTemplateRuntimeStub) Stat(string) (os.FileInfo, error) {
	if s.statInfo == nil {
		return nil, errors.New("missing")
	}
	return s.statInfo, nil
}
func (fwTemplateRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }

func (fwTemplateRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

type fwTemplateHelperRuntimeStub struct {
	runRootErr           error
	runRootWithOutput    string
	runRootWithOutputErr error
	readContent          string
	readErr              error
}

func (s fwTemplateHelperRuntimeStub) RunRoot(string) error { return s.runRootErr }

func (s fwTemplateHelperRuntimeStub) RunRootWithOutput(string) (string, error) {
	if s.runRootWithOutput == "" && s.runRootWithOutputErr == nil {
		return "stat: cannot stat: No such file or directory\nHL-RC:1\n", nil
	}
	return s.runRootWithOutput, s.runRootWithOutputErr
}

func (s fwTemplateHelperRuntimeStub) RunRootWithTimeout(string, time.Duration) (string, error) {
	return s.runRootWithOutput, s.runRootWithOutputErr
}

func (s fwTemplateHelperRuntimeStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}

func (fwTemplateHelperRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

type fwTemplateExecHostStub struct {
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s fwTemplateExecHostStub) RunRoot(cmd string) error {
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s fwTemplateExecHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput == nil {
		return "", nil
	}
	return s.runRootWithOutput(cmd)
}

func (s fwTemplateExecHostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

func (fwTemplateExecHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("missing") }

func (s fwTemplateExecHostStub) ReadRootFile(path string) (string, error) {
	if s.readRootFile == nil {
		return "", nil
	}
	return s.readRootFile(path)
}

func (s fwTemplateExecHostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile == nil {
		return nil
	}
	return s.writeRootFile(path, data, mode)
}
