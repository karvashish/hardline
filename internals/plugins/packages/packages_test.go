package packages

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

type hostStub struct {
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	stat              func(string) (os.FileInfo, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s hostStub) RunRoot(cmd string) error {
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	return nil
}

func (s hostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return "", s.RunRoot(cmd)
}

func (s hostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput != nil {
		return s.runRootWithOutput(cmd)
	}
	return "", nil
}

func (s hostStub) Stat(path string) (os.FileInfo, error) {
	if s.stat != nil {
		return s.stat(path)
	}
	return nil, errors.New("not found")
}

func (s hostStub) ReadRootFile(string) (string, error) { return "", nil }

func (s hostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile != nil {
		return s.writeRootFile(path, data, mode)
	}
	return nil
}

type fakeFileInfo struct{ mtime time.Time }

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mtime }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func agedHost(d time.Duration) hostStub {
	return hostStub{stat: func(string) (os.FileInfo, error) {
		return fakeFileInfo{mtime: time.Now().Add(-d)}, nil
	}}
}

func TestParseSinceDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"if_7d_since_last", 7 * 24 * time.Hour, false},
		{"if_1d_since_last", 24 * time.Hour, false},
		{"if_12h_since_last", 12 * time.Hour, false},
		{"if_2w_since_last", 14 * 24 * time.Hour, false},
		{"", 0, true},
		{"always", 0, true},
		{"if_d_since_last", 0, true},
		{"if_0d_since_last", 0, true},
		{"if_7x_since_last", 0, true},
		{"garbage", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseSinceDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseSinceDuration(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseSinceDuration(%q): got %v/%v, want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestValidateOpMode(t *testing.T) {
	for _, mode := range []string{"", "never", "always", "once", "if_7d_since_last"} {
		if err := ValidateOpMode("update", mode); err != nil {
			t.Errorf("mode %q: unexpected error %v", mode, err)
		}
	}
	err := ValidateOpMode("update", "sometimes")
	if err == nil || !strings.Contains(err.Error(), "invalid value") {
		t.Fatalf("expected invalid-value error, got %v", err)
	}
}

func TestShouldRun(t *testing.T) {
	for _, mode := range []string{"", "never"} {
		if run, err := ShouldRun(hostStub{}, mode, StateLastUpgrade, true); run || err != nil {
			t.Errorf("mode %q: want false/nil, got %v/%v", mode, run, err)
		}
	}
	if run, err := ShouldRun(hostStub{}, "always", StateLastUpgrade, false); !run || err != nil {
		t.Errorf("always: want true/nil, got %v/%v", run, err)
	}
	if run, _ := ShouldRun(hostStub{}, "once", StateLastUpgrade, true); !run {
		t.Error("once with wouldChange: want true")
	}
	if run, _ := ShouldRun(hostStub{}, "once", StateLastUpgrade, false); run {
		t.Error("once without wouldChange: want false")
	}
	if run, _ := ShouldRun(hostStub{}, "if_7d_since_last", StateLastUpgrade, false); !run {
		t.Error("no state file: want true")
	}
	if run, _ := ShouldRun(agedHost(8*24*time.Hour), "if_7d_since_last", StateLastUpgrade, false); !run {
		t.Error("elapsed over threshold: want true")
	}
	if run, _ := ShouldRun(agedHost(6*24*time.Hour), "if_7d_since_last", StateLastUpgrade, false); run {
		t.Error("elapsed under threshold: want false")
	}
	if _, err := ShouldRun(hostStub{}, "if_bad_since_last", StateLastUpgrade, false); err == nil {
		t.Error("invalid mode: want error")
	}
}

func TestMarkRan(t *testing.T) {
	t.Run("writes the state file", func(t *testing.T) {
		var wrote string
		host := hostStub{writeRootFile: func(path string, _ []byte, _ os.FileMode) error {
			wrote = path
			return nil
		}}
		MarkRan(host, StateLastUpdate)
		if wrote != StateLastUpdate {
			t.Fatalf("wrote %q, want %q", wrote, StateLastUpdate)
		}
	})

	t.Run("mkdir failure is not fatal", func(t *testing.T) {
		host := hostStub{runRoot: func(string) error { return errors.New("boom") }}
		MarkRan(host, StateLastUpdate)
	})

	t.Run("write failure is not fatal", func(t *testing.T) {
		host := hostStub{writeRootFile: func(string, []byte, os.FileMode) error {
			return errors.New("boom")
		}}
		MarkRan(host, StateLastUpdate)
	})
}

func TestPlanOpDecision(t *testing.T) {
	cases := []struct {
		name    string
		host    pluginapi.Host
		mode    string
		change  bool
		willRun bool
		reason  string
	}{
		{"never", hostStub{}, "never", true, false, ""},
		{"always", hostStub{}, "always", false, true, "always"},
		{"once needs change", hostStub{}, "once", true, true, "once: packages need to change"},
		{"once aligned", hostStub{}, "once", false, false, "once: packages already aligned"},
		{"never ran", hostStub{}, "if_7d_since_last", false, true, "never ran"},
		{"due", agedHost(8 * 24 * time.Hour), "if_7d_since_last", false, true, "last ran 1w ago"},
		{"not due", agedHost(2 * time.Hour), "if_7d_since_last", false, false, "ran 2h ago"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PlanOpDecision(tc.host, tc.mode, StateLastUpdate, tc.change)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.WillRun != tc.willRun {
				t.Fatalf("WillRun=%v, want %v", got.WillRun, tc.willRun)
			}
			if !strings.Contains(got.Reason, tc.reason) {
				t.Fatalf("Reason=%q, want it to contain %q", got.Reason, tc.reason)
			}
		})
	}

	if _, err := PlanOpDecision(hostStub{}, "if_bad_since_last", StateLastUpdate, false); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestFormatElapsed(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Minute:     "30m",
		3 * time.Hour:        "3h",
		50 * time.Hour:       "2d",
		15 * 24 * time.Hour:  "2w",
		100 * 24 * time.Hour: "14w",
	}
	for d, want := range cases {
		if got := FormatElapsed(d); got != want {
			t.Errorf("FormatElapsed(%v)=%q, want %q", d, got, want)
		}
	}
}

func TestNeedsWouldChange(t *testing.T) {
	if !NeedsWouldChange("once", "", "") || !NeedsWouldChange("", "once", "") || !NeedsWouldChange("", "", "once") {
		t.Fatal("expected any once mode to require the would-change probe")
	}
	if NeedsWouldChange("always", "never", "") {
		t.Fatal("expected no probe without a once mode")
	}
}

func TestValidateNames(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	if err := ValidateNames(re, []string{"vim", "g++", "libc6.1"}); err != nil {
		t.Fatalf("expected valid names to pass, got %v", err)
	}
	// The caller's rule is the whole rule: this one is lower-case only, so a
	// name another backend would accept is rejected here.
	if err := ValidateNames(re, []string{"ImageMagick"}); err == nil {
		t.Fatal("expected an upper-case name to fail a lower-case-only pattern")
	}
	for _, bad := range []string{"--force", "curl;id", "a b", "$(id)", ""} {
		if err := ValidateNames(re, []string{bad}); err == nil {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}

func TestValidateLists(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
	cases := []struct {
		name            string
		install, purge  []string
		wantErrContains string
	}{
		{"ok", []string{"curl"}, []string{"telnet"}, ""},
		{"empty install entry", []string{" "}, nil, "must not be empty"},
		{"empty purge entry", nil, []string{""}, "must not be empty"},
		{"duplicate install", []string{"curl", "curl"}, nil, "duplicated in install"},
		{"duplicate purge", nil, []string{"telnet", "telnet"}, "duplicated in purge"},
		{"install and purge", []string{"curl"}, []string{"curl"}, "cannot be both installed and purged"},
		{"bad install name", []string{"curl;id"}, nil, "invalid package name"},
		{"bad purge name", nil, []string{"telnet;id"}, "invalid package name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateLists(re, tc.install, tc.purge)
			if tc.wantErrContains == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErrContains)
			}
		})
	}
}

func TestTimeoutCmdAndAppendPackages(t *testing.T) {
	if got := TimeoutCmd("apt-get update"); !strings.HasPrefix(got, "timeout 1800 ") {
		t.Fatalf("TimeoutCmd did not apply the deadline: %q", got)
	}
	got := AppendPackages("apt-get install", []string{"curl", "we ird"})
	if got != "apt-get install 'curl' 'we ird'" {
		t.Fatalf("AppendPackages quoting is wrong: %q", got)
	}
}

func TestRunRoot(t *testing.T) {
	if err := RunRoot(hostStub{}, "true"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	host := hostStub{runRoot: func(string) error { return errors.New("boom") }}
	if err := RunRoot(host, "false"); err == nil {
		t.Fatal("expected the command failure to surface")
	}
}

func TestInstalled(t *testing.T) {
	if Installed(nil, "dpkg -s %s", "curl") {
		t.Fatal("a nil host cannot report an installed package")
	}
	var got string
	host := hostStub{runRoot: func(cmd string) error {
		got = cmd
		return nil
	}}
	if !Installed(host, "dpkg -s %s >/dev/null 2>&1", "curl") {
		t.Fatal("expected installed")
	}
	if got != "dpkg -s 'curl' >/dev/null 2>&1" {
		t.Fatalf("probe command is wrong: %q", got)
	}
	missing := hostStub{runRoot: func(string) error { return errors.New("no") }}
	if Installed(missing, "dpkg -s %s", "curl") {
		t.Fatal("expected not installed")
	}
}

func TestCheckLock(t *testing.T) {
	t.Run("no lock held", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) { return "", nil }}
		if err := CheckLock(host, "fuser x", "hint"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("lock held", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) { return "12345", nil }}
		err := CheckLock(host, "fuser x", "run lsof")
		if err == nil || !strings.Contains(err.Error(), "lock is held") || !strings.Contains(err.Error(), "run lsof") {
			t.Fatalf("expected a lock-held error carrying the hint, got %v", err)
		}
	})
	t.Run("probe failure is not an answer", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
		if err := CheckLock(host, "fuser x", "hint"); err != nil {
			t.Fatalf("a failing probe must not report a lock, got %v", err)
		}
	})
}

func TestFirstLines(t *testing.T) {
	if got := FirstLines("a\nb\nc\nd", 2); got != "a; b" {
		t.Fatalf("got %q", got)
	}
	if got := FirstLines("only", 3); got != "only" {
		t.Fatalf("got %q", got)
	}
}

func TestTargets(t *testing.T) {
	names, install, purge := Targets([]string{"curl", " ", "bash"}, []string{"telnet"})
	want := []string{"bash", "curl", "telnet"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i, n := range want {
		if names[i] != n {
			t.Fatalf("got %v, want %v (sorted)", names, want)
		}
	}
	if _, ok := install["curl"]; !ok {
		t.Fatal("curl should be in the install set")
	}
	if _, ok := purge["telnet"]; !ok {
		t.Fatal("telnet should be in the purge set")
	}
	if _, ok := install["telnet"]; ok {
		t.Fatal("telnet must not be in the install set")
	}
}

func TestCaptureNotes(t *testing.T) {
	if notes := CaptureNotes("never", "", "never"); notes != nil {
		t.Fatalf("expected no notes, got %v", notes)
	}
	notes := CaptureNotes("always", "once", "once")
	if len(notes) != 3 {
		t.Fatalf("expected three notes, got %v", notes)
	}
}

func TestWouldChange(t *testing.T) {
	if WouldChange(nil, nil) {
		t.Fatal("nothing requested cannot change anything")
	}
	if !WouldChange([]PkgInfo{{Name: "curl", Installed: false}}, nil) {
		t.Fatal("an absent install target is a change")
	}
	if !WouldChange(nil, []PkgInfo{{Name: "telnet", Installed: true}}) {
		t.Fatal("a present purge target is a change")
	}
	if WouldChange([]PkgInfo{{Name: "curl", Installed: true}}, []PkgInfo{{Name: "telnet", Installed: false}}) {
		t.Fatal("an aligned host is not a change")
	}
}

func TestRPMQuery(t *testing.T) {
	t.Run("installed with epoch", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) {
			return "HL:1:2.06-80.el9\tgrub2-tools-1:2.06-80.el9.x86_64\n", nil
		}}
		installed, version, pin, err := RPMQuery(host, "grub2-tools")
		if err != nil || !installed {
			t.Fatalf("got installed=%v err=%v", installed, err)
		}
		if version != "1:2.06-80.el9" {
			t.Fatalf("version=%q", version)
		}
		if pin != "grub2-tools-1:2.06-80.el9.x86_64" {
			t.Fatalf("pin=%q", pin)
		}
	})

	t.Run("arch-qualified request pins a valid NEVRA", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) {
			return "HL:2.34-100.el9\tglibc-2.34-100.el9.i686\n", nil
		}}
		_, _, pin, _ := RPMQuery(host, "glibc.i686")
		if !RPMPinRe.MatchString(pin) {
			t.Fatalf("pin %q is not a valid NEVRA", pin)
		}
		if strings.HasPrefix(pin, "glibc.i686-") {
			t.Fatalf("pin %q put the arch before the version", pin)
		}
	})

	t.Run("not installed", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) {
			return "package tree is not installed\n", nil
		}}
		installed, version, pin, err := RPMQuery(host, "tree")
		if err != nil || installed || version != "" || pin != "" {
			t.Fatalf("got installed=%v version=%q pin=%q err=%v", installed, version, pin, err)
		}
	})

	t.Run("answer without the NEVRA field", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) {
			return "HL:1.8.0-10.el9\n", nil
		}}
		installed, version, pin, err := RPMQuery(host, "tree")
		if err != nil || !installed || version != "1.8.0-10.el9" || pin != "" {
			t.Fatalf("got installed=%v version=%q pin=%q err=%v", installed, version, pin, err)
		}
	})

	t.Run("a spec satisfied by a provide is not absent", func(t *testing.T) {
		// dnf resolves a spec through Provides and obsoletes, so a name that no
		// rpm carries can still be installed. Recording it as absent would leave
		// rollback nothing to undo.
		var cmd string
		host := hostStub{runRootWithOutput: func(c string) (string, error) {
			cmd = c
			return "package java-21-headless is not installed\n" +
				"HL:1:21.0.5-2.el9\tjava-21-openjdk-headless-1:21.0.5-2.el9.x86_64\n", nil
		}}
		installed, version, pin, err := RPMQuery(host, "java-21-headless")
		if err != nil || !installed || version != "1:21.0.5-2.el9" {
			t.Fatalf("got installed=%v version=%q err=%v", installed, version, err)
		}
		if pin != "java-21-openjdk-headless-1:21.0.5-2.el9.x86_64" {
			t.Fatalf("pin must name the provider: %q", pin)
		}
		if !strings.Contains(cmd, "--whatprovides") {
			t.Fatalf("the name miss must be asked again as a provide: %s", cmd)
		}
	})

	t.Run("transport error", func(t *testing.T) {
		host := hostStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
		if _, _, _, err := RPMQuery(host, "tree"); err == nil {
			t.Fatal("expected the transport error to surface")
		}
	})
}

func TestUnexpectedRemovals(t *testing.T) {
	if got := UnexpectedRemovals("tree", []string{"tree"}); got != nil {
		t.Fatalf("an undo of exactly its own install is expected, got %v", got)
	}
	if got := UnexpectedRemovals("glibc.i686", []string{"glibc"}); got != nil {
		t.Fatalf("the transaction table drops the arch the request carried, got %v", got)
	}
	got := UnexpectedRemovals("tree", []string{"tree", "treeview", "libtree"})
	if len(got) != 2 || got[0] != "treeview" || got[1] != "libtree" {
		t.Fatalf("got %v", got)
	}
}

func TestRPMPatterns(t *testing.T) {
	for _, ok := range []string{"bash", "glibc.i686", "python3-libs", "lib_foo+bar"} {
		if !RPMNameRe.MatchString(ok) {
			t.Errorf("expected %q to be a valid rpm name", ok)
		}
	}
	for _, bad := range []string{"--force", "curl;id", "a b", ""} {
		if RPMNameRe.MatchString(bad) {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
	for _, ok := range []string{"bash-5.1.8-9.el9.x86_64", "grub2-tools-1:2.06-80.el9.noarch", "glibc-2.34-100.el9.i686"} {
		if !RPMPinRe.MatchString(ok) {
			t.Errorf("expected %q to be a valid NEVRA", ok)
		}
	}
	// The pattern is a bound on what may reach a root command, not a proof of
	// NEVRA ordering: rpm itself composes the pin from %{NAME} and %{ARCH}, so
	// what matters here is that nothing shell-significant gets through.
	for _, bad := range []string{
		"bash", "bash-x.y.z.x86_64", "-bash-1.0-1.x86_64",
		"bash-5.1.8-9.el9.x86_64 --allowerasing", "bash-5.1.8;id.x86_64",
		"bash-$(id)-1.x86_64", "bash-`id`-1.x86_64",
	} {
		if RPMPinRe.MatchString(bad) {
			t.Errorf("expected %q to be rejected as a pin", bad)
		}
	}
}

func TestTrimAndIsRPMArch(t *testing.T) {
	if name, ok := TrimRPMArch("bash.x86_64"); !ok || name != "bash" {
		t.Fatalf("got %q/%v", name, ok)
	}
	if _, ok := TrimRPMArch("Obsoleting"); ok {
		t.Fatal("a bare word is not a package column")
	}
	if _, ok := TrimRPMArch(".x86_64"); ok {
		t.Fatal("an empty name is not a package column")
	}
	if !IsRPMArch("noarch") || IsRPMArch("baseos") {
		t.Fatal("IsRPMArch is wrong")
	}
}

func TestParseRPMTransaction(t *testing.T) {
	const out = `Dependencies resolved.
================================================================================
 Package          Arch    Version              Repository        Size
================================================================================
Installing:
 tree             x86_64  1.8.0-10.el9         appstream         55 k
Installing dependencies:
 libfoo           x86_64  1.2-3.el9            baseos            10 k
Removing:
 oldpkg           x86_64  1.0-1.el9            @baseos           10 k

Transaction Summary
`
	got := ParseRPMTransaction(out, map[string]bool{"Installing:": true, "Installing dependencies:": true})
	if len(got) != 2 || got[0] != "tree" || got[1] != "libfoo" {
		t.Fatalf("got %v, want [tree libfoo]", got)
	}
	if rem := ParseRPMTransaction(out, map[string]bool{"Removing:": true}); len(rem) != 1 || rem[0] != "oldpkg" {
		t.Fatalf("got %v, want [oldpkg]", rem)
	}
	if none := ParseRPMTransaction("Nothing to do.\n", map[string]bool{"Installing:": true}); len(none) != 0 {
		t.Fatalf("got %v, want none", none)
	}
}

func TestRenderPlan(t *testing.T) {
	t.Run("nothing to do", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpdateMode:   "never",
			InstallInfos: []PkgInfo{{Name: "curl", Installed: true}},
			PurgeInfos:   []PkgInfo{{Name: "telnet", Installed: false}},
		})
		if got.WillChange {
			t.Fatal("an aligned host must not report a change")
		}
		if !strings.Contains(got.Summary, "no-op") {
			t.Fatalf("summary=%q", got.Summary)
		}
		if got.OperatorSummary != "Package state already matches the requested policy" {
			t.Fatalf("operator summary=%q", got.OperatorSummary)
		}
	})

	t.Run("update alone is its own summary", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpdateMode: "always",
			Update:     Decision{WillRun: true, Reason: "always"},
		})
		if !got.WillChange {
			t.Fatal("a refresh is a change")
		}
		if !strings.Contains(got.Summary, "update package index") {
			t.Fatalf("summary=%q", got.Summary)
		}
		if len(got.Diff) != 1 || !strings.Contains(got.Diff[0], "refreshed") {
			t.Fatalf("diff=%v", got.Diff)
		}
	})

	t.Run("install, purge, upgrade and autoremove", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpgradeMode:       "always",
			AutoremoveMode:    "always",
			InstallInfos:      []PkgInfo{{Name: "curl", Installed: false}},
			PurgeInfos:        []PkgInfo{{Name: "telnet", Installed: true}},
			Upgrade:           Decision{WillRun: true, Reason: "always"},
			Autoremove:        Decision{WillRun: true, Reason: "always"},
			UpgradePreview:    Preview{Packages: []string{"bash"}},
			InstallPreview:    Preview{Packages: []string{"curl", "libcurl4"}},
			AutoremovePreview: Preview{Packages: []string{"oldlib"}},
		})
		if !got.WillChange {
			t.Fatal("expected a change")
		}
		joined := strings.Join(got.Diff, "\n")
		for _, want := range []string{
			`package "bash": installed -> upgraded`,
			`package "curl": absent -> installed`,
			`package "libcurl4": absent -> installed (dependency)`,
			`package "telnet": installed -> purged`,
			`package "oldlib": installed -> removed by autoremove`,
		} {
			if !strings.Contains(joined, want) {
				t.Errorf("diff missing %q\ngot:\n%s", want, joined)
			}
		}
		// The explicit request must not be double-counted as a dependency.
		if strings.Contains(joined, `package "curl": absent -> installed (dependency)`) {
			t.Error("an explicitly requested package was also counted as a dependency")
		}
	})

	t.Run("preview failures become highlights, not errors", func(t *testing.T) {
		boom := errors.New("dnf exploded")
		got := RenderPlan(PlanInputs{
			UpgradeMode:       "always",
			AutoremoveMode:    "always",
			InstallInfos:      []PkgInfo{{Name: "curl", Installed: false}},
			Upgrade:           Decision{WillRun: true},
			Autoremove:        Decision{WillRun: true},
			UpgradePreview:    Preview{Err: boom},
			InstallPreview:    Preview{Err: boom},
			AutoremovePreview: Preview{Err: boom},
		})
		if len(got.Highlights) != 3 {
			t.Fatalf("expected one highlight per failed preview, got %v", got.Highlights)
		}
		if !got.WillChange {
			t.Fatal("the install itself is still a change")
		}
	})

	t.Run("skipped operations say why", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpdateMode:     "if_7d_since_last",
			UpgradeMode:    "once",
			AutoremoveMode: "once",
			Update:         Decision{WillRun: false, Reason: "ran 2h ago"},
			Upgrade:        Decision{WillRun: false, Reason: "once: packages already aligned"},
			Autoremove:     Decision{WillRun: false, Reason: "once: packages already aligned"},
		})
		joined := strings.Join(got.Details, "\n")
		for _, want := range []string{"update: skipped", "upgrade: skipped", "autoremove: skipped"} {
			if !strings.Contains(joined, want) {
				t.Errorf("details missing %q\ngot:\n%s", want, joined)
			}
		}
	})

	t.Run("empty previews are called out as no-ops", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpgradeMode:    "always",
			AutoremoveMode: "always",
			Update:         Decision{WillRun: true, Reason: "always"},
			UpdateMode:     "always",
			Upgrade:        Decision{WillRun: true, Reason: "always"},
			Autoremove:     Decision{WillRun: true, Reason: "always"},
		})
		joined := strings.Join(got.Details, "\n")
		if !strings.Contains(joined, "no packages would be upgraded") {
			t.Errorf("details missing the empty-upgrade note:\n%s", joined)
		}
		// After an upgrade the autoremove set can still change, and the plan
		// has to say so rather than promise a no-op.
		if !strings.Contains(joined, "may change after upgrade") {
			t.Errorf("details missing the post-upgrade caveat:\n%s", joined)
		}
		if !strings.Contains(got.Summary, "may change after update") {
			t.Errorf("summary missing the post-update caveat: %q", got.Summary)
		}
	})

	t.Run("upgrade with nothing pending and no update", func(t *testing.T) {
		got := RenderPlan(PlanInputs{
			UpgradeMode:  "always",
			Upgrade:      Decision{WillRun: true, Reason: "always"},
			InstallInfos: []PkgInfo{{Name: "curl", Installed: false}},
		})
		if !strings.Contains(got.Summary, "upgrade installed packages") {
			t.Fatalf("summary=%q", got.Summary)
		}
	})
}
