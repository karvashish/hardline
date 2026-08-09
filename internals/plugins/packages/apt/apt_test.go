package apt

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
	if strings.HasPrefix(cmd, "dpkg -s ") {
		name := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(cmd, "dpkg -s "), " >/dev/null 2>&1"), "'\"")
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

func step(t *testing.T, config map[string]any) profile.Step {
	t.Helper()
	return profile.Step{ID: "pkg", Plugin: "packages_apt", Config: config}
}

func TestPluginIdentity(t *testing.T) {
	p := Plugin()
	if p.Name != "packages_apt" {
		t.Fatalf("plugin name is %q", p.Name)
	}
	if !p.InternalValidation {
		t.Fatal("expected the plugin to declare internal validation")
	}
	for name, fn := range map[string]any{
		"Apply": p.Apply, "Plan": p.Plan, "Capture": p.Capture,
		"Rollback": p.Rollback, "DetectConflict": p.DetectConflict,
	} {
		if fn == nil {
			t.Errorf("%s is nil", name)
		}
	}
}

func TestDecodeRejectsBadConfig(t *testing.T) {
	cases := map[string]map[string]any{
		"empty config":      {},
		"unknown op mode":   {"update": "sometimes"},
		"injected name":     {"install": []any{"curl;id"}},
		"upper-case name":   {"install": []any{"ImageMagick"}},
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

	if _, err := decode(step(t, map[string]any{"install": []any{"curl"}})); err != nil {
		t.Fatalf("expected a valid config to decode, got %v", err)
	}
}

func TestApplyRunsTheRightCommands(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds, installed: map[string]bool{"telnet": true}}
	spec := &Spec{Update: "always", Upgrade: "always", Autoremove: "always",
		Install: []string{"curl"}, Purge: []string{"telnet"}}

	if err := apply(pluginapi.Context{Host: host}, spec); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"apt-get update -y", "apt-get upgrade -y",
		"apt-get install -y 'curl'", "apt-get purge -y 'telnet'",
		"apt-get autoremove -y",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "DEBIAN_FRONTEND=noninteractive") {
		t.Error("apt-get must run non-interactively")
	}
}

func TestApplySkipsAndMarks(t *testing.T) {
	t.Run("never runs nothing", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		if err := apply(pluginapi.Context{Host: host}, &Spec{Update: "never", Upgrade: "never"}); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), "apt-get") {
			t.Fatalf("expected no apt-get commands, got %v", cmds)
		}
	})

	t.Run("since_last marks the state file", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		if err := apply(pluginapi.Context{Host: host}, &Spec{Update: "if_7d_since_last"}); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "mkdir -p /var/lib/hardline") {
			t.Fatalf("expected the state dir to be created, got %v", cmds)
		}
	})

	t.Run("once consults current state", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds, installed: map[string]bool{"curl": true}}
		if err := apply(pluginapi.Context{Host: host}, &Spec{Upgrade: "once", Install: []string{"curl"}}); err != nil {
			t.Fatalf("apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), "apt-get upgrade") {
			t.Fatal("once must not upgrade when the host is already aligned")
		}
	})
}

func TestApplyFailures(t *testing.T) {
	if err := apply(pluginapi.Context{}, &Spec{Update: "always"}); err == nil ||
		!strings.Contains(err.Error(), "host context is required") {
		t.Fatalf("expected a host-required error, got %v", err)
	}

	t.Run("lock blocks apply", func(t *testing.T) {
		prev := checkLock
		defer func() { checkLock = prev }()
		checkLock = func(pluginapi.Host) error { return errors.New("package manager lock is held") }
		err := apply(pluginapi.Context{Host: hostStub{}}, &Spec{Update: "always"})
		if err == nil || !strings.Contains(err.Error(), "lock is held") {
			t.Fatalf("expected the lock error, got %v", err)
		}
	})

	for _, tc := range []struct {
		name, failOn string
		spec         *Spec
	}{
		{"update", "apt-get update", &Spec{Update: "always"}},
		{"upgrade", "apt-get upgrade", &Spec{Upgrade: "always"}},
		{"install", "apt-get install", &Spec{Install: []string{"curl"}}},
		{"purge", "apt-get purge", &Spec{Purge: []string{"telnet"}}},
		{"autoremove", "apt-get autoremove", &Spec{Autoremove: "always"}},
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

	t.Run("invalid mode surfaces from apply", func(t *testing.T) {
		if err := apply(pluginapi.Context{Host: hostStub{}}, &Spec{Autoremove: "if_bad_since_last"}); err == nil {
			t.Fatal("expected an invalid-mode error")
		}
	})
}

func TestPlan(t *testing.T) {
	host := hostStub{
		installed: map[string]bool{"telnet": true},
		output: map[string]string{
			"apt-get -s upgrade":    "Inst bash [5.1-1] (5.1-2 Debian:12)\n",
			"apt-get -s install":    "Inst curl [] (8.0-1)\nInst libcurl4 [] (8.0-1)\n",
			"apt-get -s autoremove": "Remv oldlib [1.0]\n",
		},
	}
	res, err := plan(pluginapi.Context{Host: host}, &Spec{
		Update: "always", Upgrade: "always", Autoremove: "always",
		Install: []string{"curl"}, Purge: []string{"telnet"},
	})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if !res.WillChange {
		t.Fatal("expected a change")
	}
	joined := strings.Join(res.Diff, "\n")
	for _, want := range []string{"bash", "curl", "libcurl4", "telnet", "oldlib"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diff missing %q:\n%s", want, joined)
		}
	}

	if _, err := plan(pluginapi.Context{}, &Spec{Update: "always"}); err == nil {
		t.Fatal("expected a host-required error")
	}

	for _, mode := range []string{"update", "upgrade", "autoremove"} {
		spec := &Spec{}
		switch mode {
		case "update":
			spec.Update = "if_bad_since_last"
		case "upgrade":
			spec.Upgrade = "if_bad_since_last"
		case "autoremove":
			spec.Autoremove = "if_bad_since_last"
		}
		if _, err := plan(pluginapi.Context{Host: hostStub{}}, spec); err == nil {
			t.Fatalf("expected an invalid %s mode to fail plan", mode)
		}
	}
}

func TestPlanPinsTheLocale(t *testing.T) {
	var cmds []string
	host := hostStub{cmds: &cmds}
	if _, err := plan(pluginapi.Context{Host: host}, &Spec{Upgrade: "always", Install: []string{"curl"}, Autoremove: "always"}); err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	for _, cmd := range cmds {
		if strings.Contains(cmd, "apt-get -s") && !strings.HasPrefix(cmd, "LC_ALL=C ") {
			t.Errorf("parsed command is not locale-pinned: %q", cmd)
		}
	}
}

func TestPlanIgnoresTranslatedProse(t *testing.T) {
	// apt surrounds its machine-readable Inst/Remv markers with prose that
	// gettext does translate. Only the markers may be read as packages.
	host := hostStub{output: map[string]string{
		"apt-get -s upgrade": "Paketlisten werden gelesen...\n" +
			"Abhängigkeitsbaum wird aufgebaut...\n" +
			"Inst bash [5.1-1] (5.1-2 Debian:12)\n" +
			"1 aktualisiert, 0 neu installiert, 0 zu entfernen\n",
	}}
	res, err := plan(pluginapi.Context{Host: host}, &Spec{Upgrade: "always"})
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}
	if len(res.Diff) != 1 || !strings.Contains(res.Diff[0], `package "bash"`) {
		t.Fatalf("expected only bash from the marker lines, got %v", res.Diff)
	}
}

func TestCaptureAndRestore(t *testing.T) {
	host := hostStub{
		installed: map[string]bool{"telnet": true},
		output: map[string]string{
			"dpkg-query": "install ok installed\t1.2.3-4",
		},
	}
	res, err := capture(pluginapi.Context{Host: host}, "pkg", &Spec{
		Update: "always", Install: []string{"curl"}, Purge: []string{"telnet"},
	})
	if err != nil {
		t.Fatalf("capture failed: %v", err)
	}
	if res.RollbackMode != pluginapi.ModeBestEffort {
		t.Fatalf("rollback mode is %q", res.RollbackMode)
	}
	if len(res.Objects) != 2 {
		t.Fatalf("expected two records, got %d", len(res.Objects))
	}
	if len(res.Notes) == 0 {
		t.Fatal("expected the update irreversibility note")
	}
	first := res.Objects[0].Package
	if first.Name != "curl" || first.PinSpec != "curl=1.2.3-4" {
		t.Fatalf("record is wrong: %+v", first)
	}

	if _, err := capture(pluginapi.Context{}, "pkg", &Spec{}); err == nil {
		t.Fatal("expected a host-required error")
	}

	t.Run("query failure surfaces", func(t *testing.T) {
		bad := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
		if _, err := capture(pluginapi.Context{Host: bad}, "pkg", &Spec{Install: []string{"curl"}}); err == nil {
			t.Fatal("expected the query failure to surface")
		}
	})
}

func TestRestore(t *testing.T) {
	t.Run("purges what apply installed", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		err := restore(host, pluginapi.PackageState{Name: "curl", RequestedInstall: true, WasInstalled: false})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "apt-get purge -y 'curl'") {
			t.Fatalf("expected a purge, got %v", cmds)
		}
	})

	t.Run("reinstalls at the pinned version", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		err := restore(host, pluginapi.PackageState{
			Name: "telnet", RequestedPurge: true, WasInstalled: true,
			Version: "1.2.3-4", PinSpec: "telnet=1.2.3-4",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "'telnet=1.2.3-4'") {
			t.Fatalf("expected the pinned install, got %v", cmds)
		}
	})

	t.Run("a malformed pin is not used", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds}
		err := restore(host, pluginapi.PackageState{
			Name: "telnet", RequestedPurge: true, WasInstalled: true,
			PinSpec: "telnet=1.2.3-4 --allow-downgrades",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		if strings.Contains(joined, "--allow-downgrades") {
			t.Fatalf("a malformed pin reached the command line: %v", cmds)
		}
		if !strings.Contains(joined, "apt-get install -y 'telnet'") {
			t.Fatalf("expected the unpinned fallback, got %v", cmds)
		}
	})

	t.Run("falls back when the pinned install fails", func(t *testing.T) {
		var cmds []string
		host := hostStub{cmds: &cmds, runRoot: func(cmd string) error {
			if strings.Contains(cmd, "telnet=1.2.3-4") {
				return errors.New("version not available")
			}
			return nil
		}}
		err := restore(host, pluginapi.PackageState{
			Name: "telnet", RequestedPurge: true, WasInstalled: true, PinSpec: "telnet=1.2.3-4",
		})
		if err != nil {
			t.Fatalf("restore failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "apt-get install -y 'telnet'") {
			t.Fatalf("expected the unpinned fallback, got %v", cmds)
		}
	})

	t.Run("rejects a bad name from a tampered journal", func(t *testing.T) {
		if err := restore(hostStub{}, pluginapi.PackageState{Name: "curl;id", RequestedInstall: true}); err == nil {
			t.Fatal("expected the name to be rejected")
		}
		if err := restore(hostStub{}, pluginapi.PackageState{Name: "  "}); err == nil {
			t.Fatal("expected an empty name to be rejected")
		}
	})

	t.Run("failures surface", func(t *testing.T) {
		host := hostStub{runRoot: func(string) error { return errors.New("boom") }}
		if err := restore(host, pluginapi.PackageState{Name: "curl", RequestedInstall: true}); err == nil {
			t.Fatal("expected the purge failure to surface")
		}
		if err := restore(host, pluginapi.PackageState{Name: "curl", RequestedPurge: true, WasInstalled: true}); err == nil {
			t.Fatal("expected the reinstall failure to surface")
		}
	})
}

func TestConflict(t *testing.T) {
	t.Run("no conflict", func(t *testing.T) {
		host := hostStub{installed: map[string]bool{"curl": true}}
		if got := conflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true}); got != nil {
			t.Fatalf("expected no conflict, got %v", got)
		}
	})

	t.Run("removed since apply", func(t *testing.T) {
		got := conflict(hostStub{}, pluginapi.PackageState{Name: "curl", WasInstalled: true})
		if len(got) != 1 || !strings.Contains(got[0], "changed since apply") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("upgraded since apply", func(t *testing.T) {
		host := hostStub{
			installed: map[string]bool{"curl": true},
			output:    map[string]string{"dpkg-query": "install ok installed\t9.9.9"},
		}
		got := conflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: "1.2.3-4"})
		if len(got) != 1 || !strings.Contains(got[0], "upgraded since apply") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty name", func(t *testing.T) {
		if got := conflict(hostStub{}, pluginapi.PackageState{Name: " "}); got != nil {
			t.Fatalf("got %v", got)
		}
	})
}

func TestQuery(t *testing.T) {
	t.Run("installed with a version", func(t *testing.T) {
		host := hostStub{output: map[string]string{"dpkg-query": "install ok installed\t1.2.3-4"}}
		ok, version, pin, err := query(host, "curl")
		if err != nil || !ok || version != "1.2.3-4" || pin != "curl=1.2.3-4" {
			t.Fatalf("got %v/%q/%q/%v", ok, version, pin, err)
		}
	})

	t.Run("installed without a version", func(t *testing.T) {
		host := hostStub{output: map[string]string{"dpkg-query": "install ok installed"}}
		ok, version, pin, err := query(host, "curl")
		if err != nil || !ok || version != "" || pin != "" {
			t.Fatalf("got %v/%q/%q/%v", ok, version, pin, err)
		}
	})

	t.Run("not installed", func(t *testing.T) {
		ok, _, _, err := query(hostStub{}, "curl")
		if err != nil || ok {
			t.Fatalf("got %v/%v", ok, err)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
		if _, _, _, err := query(host, "curl"); err == nil {
			t.Fatal("expected the error to surface")
		}
	})
}

func TestPluginWiring(t *testing.T) {
	p := Plugin()
	bad := step(t, map[string]any{"install": []any{"curl;id"}})

	if err := p.Apply(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Apply must reject an invalid config")
	}
	if _, err := p.Plan(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Plan must reject an invalid config")
	}
	if _, err := p.Capture(pluginapi.Context{Host: hostStub{}}, bad); err == nil {
		t.Fatal("Capture must reject an invalid config")
	}

	good := step(t, map[string]any{"install": []any{"curl"}})
	if _, err := p.Capture(pluginapi.Context{Host: hostStub{}}, good); err != nil {
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
