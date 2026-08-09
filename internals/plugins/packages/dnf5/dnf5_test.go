package dnf5

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

type hostStub struct {
	installed map[string]bool
	cmds      *[]string
	output    map[string]string

	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	stat              func(string) (os.FileInfo, error)
}

func (s hostStub) record(cmd string) {
	if s.cmds != nil {
		*s.cmds = append(*s.cmds, cmd)
	}
}

func (s hostStub) RunRoot(cmd string) error {
	s.record(cmd)
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	if strings.HasPrefix(cmd, "rpm -q ") {
		name := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(cmd, "rpm -q "), " >/dev/null 2>&1"), "'\"")
		if s.installed[name] {
			return nil
		}
		return errors.New("not installed")
	}
	return nil
}

func (s hostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return "", s.RunRoot(cmd)
}

func (s hostStub) RunRootWithOutput(cmd string) (string, error) {
	s.record(cmd)
	if s.runRootWithOutput != nil {
		return s.runRootWithOutput(cmd)
	}
	for marker, out := range s.output {
		if strings.Contains(cmd, marker) {
			return out, nil
		}
	}
	return "", nil
}

func (s hostStub) Stat(path string) (os.FileInfo, error) {
	if s.stat != nil {
		return s.stat(path)
	}
	return nil, errors.New("not found")
}

func (s hostStub) ReadRootFile(string) (string, error)             { return "", nil }
func (s hostStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

// dnf5 prints obsoletes in the same flat listing, with no trailing section.
const checkUpgradeOutput = `Last metadata expiration check: 0:00:01 ago on Mon 01 Jan 2026.

bash.x86_64                    5.1.8-9.el9_4          baseos
kernel.x86_64                  5.14.0-503.el9         baseos
bash.x86_64                    5.1.8-9.el9_4          baseos
grub2-tools.x86_64             1:2.06-80.el9          baseos
`

const installOutput = `Dependencies resolved.
================================================================================
 Package          Arch    Version              Repository        Size
================================================================================
Installing:
 tree             x86_64  1.8.0-10.el9         appstream         55 k
Installing dependencies:
 libfoo           x86_64  1.2-3.el9            baseos            10 k

Transaction Summary
================================================================================
Install  2 Packages
Operation aborted.
`

const removeOutput = `Dependencies resolved.
================================================================================
Removing:
 oldpkg           x86_64  1.0-1.el9            @baseos           10 k
Removing unused dependencies:
 oldlib           noarch  2.0-1.el9            @baseos            5 k

Transaction Summary
Operation aborted.
`

func step(t *testing.T, config map[string]any) profile.Step {
	t.Helper()
	return profile.Step{ID: "pkg", Plugin: "packages_dnf5", Config: config}
}

func TestPluginIdentity(t *testing.T) {
	p := Plugin()
	if p.Name != "packages_dnf5" {
		t.Fatalf("plugin name is %q", p.Name)
	}
	if !p.InternalValidation {
		t.Fatal("expected the plugin to declare internal validation")
	}
}

func TestDecodeRejectsBadConfig(t *testing.T) {
	cases := map[string]map[string]any{
		"empty config":      {},
		"unknown op mode":   {"upgrade": "sometimes"},
		"injected name":     {"install": []any{"curl;id"}},
		"duplicate":         {"install": []any{"curl", "curl"}},
		"install and purge": {"install": []any{"curl"}, "purge": []any{"curl"}},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decode(step(t, config)); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	// rpm names are case-sensitive and may be arch-qualified, unlike apt's.
	for _, ok := range []string{"ImageMagick", "glibc.i686", "python3-libs"} {
		if _, err := decode(step(t, map[string]any{"install": []any{ok}})); err != nil {
			t.Fatalf("expected %q to be accepted, got %v", ok, err)
		}
	}
}

func TestApplyRunsTheRightCommands(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, installed: map[string]bool{"telnet": true}}
	spec := &Spec{Update: "always", Upgrade: "always", Autoremove: "always",
		Install: []string{"tree"}, Purge: []string{"telnet"}}

	if err := apply(pluginapi.Context{Host: host}, spec); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"dnf -q -y makecache --refresh", "dnf -y upgrade",
		"dnf -y install 'tree'", "dnf -y remove 'telnet'", "dnf -y autoremove",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestApplyFailures(t *testing.T) {
	if err := apply(pluginapi.Context{}, &Spec{Update: "always"}); err == nil {
		t.Fatal("expected a host-required error")
	}

	t.Run("lock blocks apply", func(t *testing.T) {
		prev := checkLock
		defer func() { checkLock = prev }()
		checkLock = func(pluginapi.Host) error { return errors.New("package manager lock is held") }
		if err := apply(pluginapi.Context{Host: hostStub{}}, &Spec{Update: "always"}); err == nil {
			t.Fatal("expected the lock error")
		}
	})

	for _, tc := range []struct {
		name, failOn string
		spec         *Spec
	}{
		{"update", "makecache", &Spec{Update: "always"}},
		{"upgrade", "dnf -y upgrade", &Spec{Upgrade: "always"}},
		{"install", "dnf -y install", &Spec{Install: []string{"tree"}}},
		{"purge", "dnf -y remove", &Spec{Purge: []string{"telnet"}}},
		{"autoremove", "dnf -y autoremove", &Spec{Autoremove: "always"}},
	} {
		t.Run(tc.name+" failure surfaces", func(t *testing.T) {
			host := hostStub{runRoot: func(cmd string) error {
				if strings.Contains(cmd, tc.failOn) {
					return errors.New("boom")
				}
				return nil
			}}
			if err := apply(pluginapi.Context{Host: host}, tc.spec); err == nil {
				t.Fatalf("expected the %s failure to surface", tc.name)
			}
		})
	}

	t.Run("invalid modes surface", func(t *testing.T) {
		if err := apply(pluginapi.Context{Host: hostStub{}}, &Spec{Update: "if_bad_since_last"}); err == nil {
			t.Fatal("expected an invalid update mode to fail")
		}
		if err := apply(pluginapi.Context{Host: hostStub{}}, &Spec{Autoremove: "if_bad_since_last"}); err == nil {
			t.Fatal("expected an invalid autoremove mode to fail")
		}
	})

	t.Run("once and since_last", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds, installed: map[string]bool{"tree": true}}
		if err := apply(pluginapi.Context{Host: host}, &Spec{Upgrade: "once", Install: []string{"tree"}}); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), "dnf -y upgrade") {
			t.Fatal("once must not upgrade an aligned host")
		}

		cmds = nil
		if err := apply(pluginapi.Context{Host: host}, &Spec{Autoremove: "if_7d_since_last"}); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "mkdir -p /var/lib/hardline") {
			t.Fatalf("expected the state file to be marked, got %v", cmds)
		}
	})
}

func TestParseCheckUpgradeReadsTheFlatListing(t *testing.T) {
	got := parseCheckUpgrade(checkUpgradeOutput)
	want := map[string]bool{"bash": true, "kernel": true, "grub2-tools": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("unexpected package %q", name)
		}
	}
	if len(parseCheckUpgrade("Last metadata expiration check: 0:00:01 ago.\n")) != 0 {
		t.Error("a bare banner is not a package listing")
	}
}

func TestPreviewsPinTheLocale(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds}
	if _, err := upgradePreview(host); err != nil {
		t.Fatalf("upgradePreview failed: %v", err)
	}
	if _, err := installPreview(host, []string{"tree"}); err == nil {
		t.Fatal("an empty transaction preview must be an error, not silence")
	}
	if _, err := autoremovePreview(host); err == nil {
		t.Fatal("an empty transaction preview must be an error, not silence")
	}
	for _, cmd := range cmds {
		if !strings.HasPrefix(cmd, "LC_ALL=C ") {
			t.Errorf("parsed command is not locale-pinned: %q", cmd)
		}
	}
}

func TestPreviewsTranslateOnlyTheirOwnExitCodes(t *testing.T) {
	if !strings.Contains(checkUpgradeCmd, `[ "$rc" = 100 ]`) {
		t.Error("check-upgrade must translate exit 100 only")
	}
	if !strings.Contains(assumeNoTail, `[ "$rc" = 1 ]`) {
		t.Error("a declined transaction must translate exit 1 only")
	}
}

func TestParseTransaction(t *testing.T) {
	got, err := parseTransaction(installOutput, installSections)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(got) != 2 || got[0] != "tree" || got[1] != "libfoo" {
		t.Fatalf("got %v", got)
	}

	rem, err := parseTransaction(removeOutput, removeSections)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(rem) != 2 {
		t.Fatalf("got %v", rem)
	}

	if _, err := parseTransaction("Nothing to do.\n", installSections); err != nil {
		t.Fatalf("an explicit no-op is a valid preview: %v", err)
	}
}

func TestParseTransactionRejectsLocalizedOutput(t *testing.T) {
	// dnf renders its banners and section headings through gettext. Without
	// LC_ALL=C the parser cannot find them, and reporting that as an empty
	// transaction would let plan promise a no-op that apply then contradicts.
	const german = `Abhängigkeiten sind aufgelöst.
================================================================================
Installieren:
 tree             x86_64  1.8.0-10.el9         appstream         55 k

Zusammenfassung der Transaktion
`
	if _, err := parseTransaction(german, installSections); err == nil {
		t.Fatal("localized output must be reported as a failed preview, not an empty one")
	}
}

func TestPlan(t *testing.T) {
	host := hostStub{
		installed: map[string]bool{"telnet": true},
		output: map[string]string{
			"check-upgrade":  checkUpgradeOutput,
			"install 'tree'": installOutput,
			"autoremove":     removeOutput,
		},
	}
	res, err := plan(pluginapi.Context{Host: host}, &Spec{
		Upgrade: "always", Autoremove: "always",
		Install: []string{"tree"}, Purge: []string{"telnet"},
	})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if !res.WillChange {
		t.Fatal("expected a change")
	}
	joined := strings.Join(res.Diff, "\n")
	for _, want := range []string{"bash", "grub2-tools", "tree", "libfoo", "telnet", "oldpkg"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diff missing %q:\n%s", want, joined)
		}
	}

	if _, err := plan(pluginapi.Context{}, &Spec{}); err == nil {
		t.Fatal("expected a host-required error")
	}
	for _, spec := range []*Spec{
		{Update: "if_bad_since_last"},
		{Upgrade: "if_bad_since_last"},
		{Autoremove: "if_bad_since_last"},
	} {
		if _, err := plan(pluginapi.Context{Host: hostStub{}}, spec); err == nil {
			t.Fatal("expected an invalid mode to fail plan")
		}
	}
}

func TestPlanReportsPreviewFailure(t *testing.T) {
	host := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
	res, err := plan(pluginapi.Context{Host: host}, &Spec{Upgrade: "always"})
	if err != nil {
		t.Fatalf("a preview failure must not abandon the plan: %v", err)
	}
	if len(res.Highlights) == 0 {
		t.Fatal("expected the preview failure to be highlighted")
	}
}

func TestCaptureAndRestore(t *testing.T) {
	host := hostStub{
		installed: map[string]bool{"telnet": true},
		output:    map[string]string{"--qf": "HL:1.8.0-10.el9\ttree-1.8.0-10.el9.x86_64\n"},
	}
	res, err := capture(pluginapi.Context{Host: host}, "pkg", &Spec{
		Upgrade: "always", Install: []string{"tree"}, Purge: []string{"telnet"},
	})
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("expected two records, got %d", len(res.Objects))
	}
	if res.Objects[0].Package.PinSpec != "tree-1.8.0-10.el9.x86_64" {
		t.Fatalf("pin is wrong: %+v", res.Objects[0].Package)
	}

	if _, err := capture(pluginapi.Context{}, "pkg", &Spec{}); err == nil {
		t.Fatal("expected a host-required error")
	}
	bad := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
	if _, err := capture(pluginapi.Context{Host: bad}, "pkg", &Spec{Install: []string{"tree"}}); err == nil {
		t.Fatal("expected the query failure to surface")
	}
}

func TestRestore(t *testing.T) {
	t.Run("removes what apply installed", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		if err := restore(host, pluginapi.PackageState{Name: "tree", RequestedInstall: true}); err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "dnf -y remove 'tree'") {
			t.Fatalf("got %v", cmds)
		}
	})

	t.Run("reinstalls at the pinned NEVRA", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		err := restore(host, pluginapi.PackageState{
			Name: "glibc.i686", RequestedPurge: true, WasInstalled: true,
			Version: "2.34-100.el9", PinSpec: "glibc-2.34-100.el9.i686",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "'glibc-2.34-100.el9.i686'") {
			t.Fatalf("expected the NEVRA install, got %v", cmds)
		}
	})

	t.Run("a malformed pin is not used", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		err := restore(host, pluginapi.PackageState{
			Name: "tree", RequestedPurge: true, WasInstalled: true,
			PinSpec: "tree-1.8.0-10.el9.x86_64 --allowerasing",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		if strings.Contains(joined, "--allowerasing") {
			t.Fatalf("a malformed pin reached the command line: %v", cmds)
		}
		if !strings.Contains(joined, "dnf -y install 'tree'") {
			t.Fatalf("expected the unpinned fallback, got %v", cmds)
		}
	})

	t.Run("falls back when the pinned install fails", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds, runRoot: func(cmd string) error {
			if strings.Contains(cmd, "1.8.0-10.el9.x86_64") {
				return errors.New("no such version")
			}
			return nil
		}}
		err := restore(host, pluginapi.PackageState{
			Name: "tree", RequestedPurge: true, WasInstalled: true,
			PinSpec: "tree-1.8.0-10.el9.x86_64",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "dnf -y install 'tree'") {
			t.Fatalf("expected the unpinned fallback, got %v", cmds)
		}
	})

	t.Run("rejects a bad name from a tampered journal", func(t *testing.T) {
		if err := restore(hostStub{}, pluginapi.PackageState{Name: "tree;id", RequestedInstall: true}); err == nil {
			t.Fatal("expected the name to be rejected")
		}
		if err := restore(hostStub{}, pluginapi.PackageState{Name: " "}); err == nil {
			t.Fatal("expected an empty name to be rejected")
		}
	})

	t.Run("failures surface", func(t *testing.T) {
		host := hostStub{runRoot: func(string) error { return errors.New("boom") }}
		if err := restore(host, pluginapi.PackageState{Name: "tree", RequestedInstall: true}); err == nil {
			t.Fatal("expected the remove failure to surface")
		}
		if err := restore(host, pluginapi.PackageState{Name: "tree", RequestedPurge: true, WasInstalled: true}); err == nil {
			t.Fatal("expected the reinstall failure to surface")
		}
	})
}

func TestConflict(t *testing.T) {
	if got := conflict(hostStub{installed: map[string]bool{"tree": true}},
		pluginapi.PackageState{Name: "tree", WasInstalled: true}); got != nil {
		t.Fatalf("expected no conflict, got %v", got)
	}
	if got := conflict(hostStub{}, pluginapi.PackageState{Name: "tree", WasInstalled: true}); len(got) != 1 {
		t.Fatalf("expected a removed-since-apply conflict, got %v", got)
	}
	host := hostStub{
		installed: map[string]bool{"tree": true},
		output:    map[string]string{"--qf": "HL:9.9.9\ttree-9.9.9.x86_64\n"},
	}
	got := conflict(host, pluginapi.PackageState{Name: "tree", WasInstalled: true, Version: "1.8.0-10.el9"})
	if len(got) != 1 || !strings.Contains(got[0], "upgraded since apply") {
		t.Fatalf("got %v", got)
	}
	if got := conflict(hostStub{}, pluginapi.PackageState{Name: " "}); got != nil {
		t.Fatalf("got %v", got)
	}
}

func TestPluginWiring(t *testing.T) {
	p := Plugin()
	bad := step(t, map[string]any{"install": []any{"tree;id"}})
	if err := p.Apply(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Apply must reject an invalid config")
	}
	if _, err := p.Plan(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Plan must reject an invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Capture must reject an invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{Host: hostStub{}}, step(t, map[string]any{"install": []any{"tree"}})); err != nil {
		t.Fatalf("Capture failed: %v", err)
	}
	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
		t.Fatalf("a validate record rolls back to nothing: %v", err)
	}
	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}); err == nil {
		t.Fatal("a package record with no snapshot must fail")
	}
	if err := p.Rollback(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); err == nil {
		t.Fatal("this plugin cannot roll back a file")
	}
	if got := p.DetectConflict(hostStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); got != nil {
		t.Fatalf("expected no conflicts for a foreign kind, got %v", got)
	}
}
