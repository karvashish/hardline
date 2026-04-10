package packages

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

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
		{"if_30d_since_last", 30 * 24 * time.Hour, false},
		{"", 0, true},
		{"always", 0, true},
		{"if_d_since_last", 0, true},
		{"if_0d_since_last", 0, true},
		{"if_7x_since_last", 0, true},
		{"garbage", 0, true},
	}
	for _, tc := range cases {
		got, err := parseSinceDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSinceDuration(%q): expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSinceDuration(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSinceDuration(%q): got %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestShouldRun(t *testing.T) {
	t.Run("never/empty → false", func(t *testing.T) {
		for _, mode := range []string{"", "never"} {
			run, err := shouldRun(packagesRuntimeStub{}, mode, stateLastUpgrade, true)
			if err != nil || run {
				t.Errorf("mode=%q: want false/nil, got run=%v err=%v", mode, run, err)
			}
		}
	})

	t.Run("always → true", func(t *testing.T) {
		run, err := shouldRun(packagesRuntimeStub{}, "always", stateLastUpgrade, false)
		if err != nil || !run {
			t.Fatalf("expected true/nil, got run=%v err=%v", run, err)
		}
	})

	t.Run("once with wouldChange=true → true", func(t *testing.T) {
		run, err := shouldRun(packagesRuntimeStub{}, "once", stateLastUpgrade, true)
		if err != nil || !run {
			t.Fatalf("expected true/nil, got run=%v err=%v", run, err)
		}
	})

	t.Run("once with wouldChange=false → false", func(t *testing.T) {
		run, err := shouldRun(packagesRuntimeStub{}, "once", stateLastUpgrade, false)
		if err != nil || run {
			t.Fatalf("expected false/nil, got run=%v err=%v", run, err)
		}
	})

	t.Run("since_last: state file absent → true", func(t *testing.T) {

		run, err := shouldRun(packagesRuntimeStub{}, "if_7d_since_last", stateLastUpgrade, false)
		if err != nil || !run {
			t.Fatalf("expected true/nil when no state file, got run=%v err=%v", run, err)
		}
	})

	t.Run("since_last: elapsed exceeds threshold → true", func(t *testing.T) {
		rt := packagesRuntimeStub{stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{mtime: time.Now().Add(-8 * 24 * time.Hour)}, nil
		}}
		run, err := shouldRun(rt, "if_7d_since_last", stateLastUpgrade, false)
		if err != nil || !run {
			t.Fatalf("expected true/nil, got run=%v err=%v", run, err)
		}
	})

	t.Run("since_last: elapsed under threshold → false", func(t *testing.T) {
		rt := packagesRuntimeStub{stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{mtime: time.Now().Add(-6 * 24 * time.Hour)}, nil
		}}
		run, err := shouldRun(rt, "if_7d_since_last", stateLastUpgrade, false)
		if err != nil || run {
			t.Fatalf("expected false/nil, got run=%v err=%v", run, err)
		}
	})

	t.Run("invalid mode → error", func(t *testing.T) {
		_, err := shouldRun(packagesRuntimeStub{}, "if_bad_since_last", stateLastUpgrade, false)
		if err == nil {
			t.Fatal("expected error for invalid mode")
		}
	})
}

func TestValidatePackageNames(t *testing.T) {
	t.Run("accepts valid names", func(t *testing.T) {
		if err := validatePackageNames([]string{"vim", "lib2to3", "g++", "libc6.1"}); err != nil {
			t.Fatalf("expected valid package names to pass, got %v", err)
		}
	})

	t.Run("rejects shell metacharacters", func(t *testing.T) {
		for _, name := range []string{"$(touch /tmp/pwned)", "`id`", "vim;id", "vim|cat", "vim extra"} {
			err := validatePackageNames([]string{name})
			if err == nil || !strings.Contains(err.Error(), "invalid package name") {
				t.Fatalf("expected invalid package name error for %q, got %v", name, err)
			}
		}
	})
}

func TestApply(t *testing.T) {
	t.Run("invalid package names fail before touching host", func(t *testing.T) {
		var called bool
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot: func(string) error {
				called = true
				return nil
			},
			runRootWithOutput: func(string) (string, error) {
				called = true
				return "", nil
			},
		}}, &Spec{Install: []string{"$(touch /tmp/pwned)"}})
		if err == nil || !strings.Contains(err.Error(), "invalid package name") {
			t.Fatalf("expected invalid package name error, got %v", err)
		}
		if called {
			t.Fatal("expected invalid package validation to happen before touching the host")
		}
	})

	t.Run("always: success runs commands in order", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{
			Update:     "always",
			Upgrade:    "always",
			Install:    []string{"a", "b"},
			Purge:      []string{"c"},
			Autoremove: "always",
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		want := []string{
			fmt.Sprintf("timeout %d apt-get update -y", aptTimeoutSeconds),
			fmt.Sprintf("timeout %d apt-get upgrade -y", aptTimeoutSeconds),
			fmt.Sprintf("timeout %d apt-get install -y 'a' 'b'", aptTimeoutSeconds),
			fmt.Sprintf("timeout %d apt-get purge -y 'c'", aptTimeoutSeconds),
			fmt.Sprintf("timeout %d apt-get autoremove -y", aptTimeoutSeconds),
		}
		if strings.Join(cmds, "|") != strings.Join(want, "|") {
			t.Fatalf("unexpected command sequence: got=%v want=%v", cmds, want)
		}
	})

	t.Run("once: skipped when packages already installed", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			installed: map[string]bool{"a": true, "b": true},
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{
			Upgrade:    "once",
			Autoremove: "once",
			Install:    []string{"a", "b"},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		for _, cmd := range cmds {
			if strings.Contains(cmd, "apt-get upgrade") || strings.Contains(cmd, "apt-get autoremove") {
				t.Fatalf("upgrade/autoremove should be skipped when packages already installed, got cmd: %q", cmd)
			}
		}
	})

	t.Run("once: runs when packages need installing", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				if strings.HasPrefix(cmd, "dpkg -s ") {
					return errors.New("not installed")
				}
				return nil
			},
		}}, &Spec{
			Upgrade:    "once",
			Autoremove: "once",
			Install:    []string{"a"},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(cmds, "|")
		if !strings.Contains(joined, "apt-get upgrade") {
			t.Fatalf("upgrade should run when packages need installing, cmds: %v", cmds)
		}
		if !strings.Contains(joined, "apt-get autoremove") {
			t.Fatalf("autoremove should run when packages need installing, cmds: %v", cmds)
		}
	})

	t.Run("since_last: writes state file after running", func(t *testing.T) {
		var written []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot:           func(cmd string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "", nil },
			writeRootFile: func(path string, _ []byte, _ os.FileMode) error {
				written = append(written, path)
				return nil
			},
		}}, &Spec{
			Upgrade: "if_7d_since_last",
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		found := false
		for _, p := range written {
			if p == stateLastUpgrade {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected state file %q to be written, got: %v", stateLastUpgrade, written)
		}
	})

	t.Run("since_last: does not write state file when skipped", func(t *testing.T) {
		var written []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			stat: func(string) (os.FileInfo, error) {
				return fakeFileInfo{mtime: time.Now().Add(-1 * time.Hour)}, nil
			},
			runRoot: func(cmd string) error { return nil },
			writeRootFile: func(path string, _ []byte, _ os.FileMode) error {
				written = append(written, path)
				return nil
			},
		}}, &Spec{
			Upgrade: "if_7d_since_last",
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		for _, p := range written {
			if p == stateLastUpgrade {
				t.Fatalf("state file should not be written when operation is skipped")
			}
		}
	})

	t.Run("invalid update mode → error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{Update: "bad"})
		if err == nil || !strings.Contains(err.Error(), "invalid update mode") {
			t.Fatalf("expected invalid update mode error, got %v", err)
		}
	})

	t.Run("invalid upgrade mode → error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{Upgrade: "bad"})
		if err == nil || !strings.Contains(err.Error(), "invalid upgrade mode") {
			t.Fatalf("expected invalid upgrade mode error, got %v", err)
		}
	})

	t.Run("invalid autoremove mode → error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{Autoremove: "bad"})
		if err == nil || !strings.Contains(err.Error(), "invalid autoremove mode") {
			t.Fatalf("expected invalid autoremove mode error, got %v", err)
		}
	})

	t.Run("since_last: writes state files for update and autoremove", func(t *testing.T) {
		var written []string
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot: func(cmd string) error { return nil },
			writeRootFile: func(path string, _ []byte, _ os.FileMode) error {
				written = append(written, path)
				return nil
			},
		}}, &Spec{
			Update:     "if_7d_since_last",
			Autoremove: "if_7d_since_last",
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		wantPaths := map[string]bool{stateLastUpdate: false, stateLastAutoremove: false}
		for _, p := range written {
			wantPaths[p] = true
		}
		if !wantPaths[stateLastUpdate] {
			t.Fatalf("expected state file %q to be written, got: %v", stateLastUpdate, written)
		}
		if !wantPaths[stateLastAutoremove] {
			t.Fatalf("expected state file %q to be written, got: %v", stateLastAutoremove, written)
		}
	})

	tests := []struct {
		name    string
		spec    Spec
		failCmd string
		wantSub string
	}{
		{name: "update error", spec: Spec{Update: "always"}, failCmd: fmt.Sprintf("timeout %d apt-get update -y", aptTimeoutSeconds), wantSub: "apt-get update failed"},
		{name: "upgrade error", spec: Spec{Upgrade: "always"}, failCmd: fmt.Sprintf("timeout %d apt-get upgrade -y", aptTimeoutSeconds), wantSub: "apt-get upgrade failed"},
		{name: "install error", spec: Spec{Install: []string{"x"}}, failCmd: fmt.Sprintf("timeout %d apt-get install -y 'x'", aptTimeoutSeconds), wantSub: "apt-get install failed"},
		{name: "purge error", spec: Spec{Purge: []string{"x"}}, failCmd: fmt.Sprintf("timeout %d apt-get purge -y 'x'", aptTimeoutSeconds), wantSub: "apt-get purge failed"},
		{name: "autoremove error", spec: Spec{Autoremove: "always"}, failCmd: fmt.Sprintf("timeout %d apt-get autoremove -y", aptTimeoutSeconds), wantSub: "apt-get autoremove failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Apply(pluginapi.Context{Host: packagesRuntimeStub{
				runRoot: func(cmd string) error {
					if cmd == tc.failCmd {
						return errors.New("boom")
					}
					return nil
				},
			}}, &tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q error, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestPlan(t *testing.T) {
	t.Run("invalid package names fail before touching host", func(t *testing.T) {
		var called bool
		_, err := Plan(pluginapi.Context{Host: packagesRuntimeStub{
			runRoot: func(string) error {
				called = true
				return nil
			},
			runRootWithOutput: func(string) (string, error) {
				called = true
				return "", nil
			},
			stat: func(string) (os.FileInfo, error) {
				called = true
				return nil, errors.New("not found")
			},
		}}, &Spec{Purge: []string{"vim | cat"}})
		if err == nil || !strings.Contains(err.Error(), "invalid package name") {
			t.Fatalf("expected invalid package name error, got %v", err)
		}
		if called {
			t.Fatal("expected invalid package validation to happen before touching the host")
		}
	})

	t.Run("rich change path", func(t *testing.T) {
		rt := packagesRuntimeStub{
			installed: map[string]bool{"a": true, "c": true},
			upgrade:   []string{"openssl"},
			install:   []string{"a", "b", "dep1"},
			auto:      []string{"oldpkg"},
		}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{
			Update:     "always",
			Upgrade:    "always",
			Install:    []string{"a", "b"},
			Purge:      []string{"c", "d"},
			Autoremove: "always",
		})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected WillChange=true for changed plan, got false")
		}
		if !strings.Contains(res.Summary, "upgrade") {
			t.Fatalf("unexpected summary: %q", res.Summary)
		}
		if len(res.Details) == 0 {
			t.Fatalf("expected details")
		}
		joinedDiff := strings.Join(res.Diff, "\n")
		for _, want := range []string{
			`package index metadata: current -> refreshed from configured repositories`,
			`package "b": absent -> installed`,
			`package "dep1": absent -> installed (dependency)`,
			`package "c": installed -> purged`,
			`package "oldpkg": installed -> removed by autoremove`,
		} {
			if !strings.Contains(joinedDiff, want) {
				t.Fatalf("expected diff %q, got %s", want, joinedDiff)
			}
		}
	})

	t.Run("full noop", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange || !strings.Contains(res.Summary, "no-op") {
			t.Fatalf("expected noop summary, got %+v", res)
		}
		if len(res.Diff) != 0 {
			t.Fatalf("expected noop plan to have no diff, got %+v", res.Diff)
		}
	})

	t.Run("update only partial noop", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{Update: "always", Upgrade: "always", Autoremove: "always"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected WillChange=true for update-only plan, got false")
		}
		if !strings.Contains(res.Summary, "may change after update") {
			t.Fatalf("unexpected partial noop summary: %q", res.Summary)
		}
	})

	t.Run("once: skipped when packages aligned", func(t *testing.T) {
		rt := packagesRuntimeStub{installed: map[string]bool{"a": true}}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{
			Upgrade:    "once",
			Autoremove: "once",
			Install:    []string{"a"},
		})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange {
			t.Fatalf("expected WillChange=false when packages aligned and mode=once, got true")
		}
		joined := strings.Join(res.Details, "\n")
		if !strings.Contains(joined, "skipped") {
			t.Fatalf("expected 'skipped' in details, got: %s", joined)
		}
	})

	t.Run("once: runs when packages need work", func(t *testing.T) {
		rt := packagesRuntimeStub{
			installed: map[string]bool{},
			upgrade:   []string{"pkg1"},
			auto:      []string{"old"},
		}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{
			Upgrade:    "once",
			Autoremove: "once",
			Install:    []string{"a"},
		})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected WillChange=true, got false")
		}
	})

	t.Run("since_last: shows skipped reason when recently ran", func(t *testing.T) {
		rt := packagesRuntimeStub{
			stat: func(string) (os.FileInfo, error) {
				return fakeFileInfo{mtime: time.Now().Add(-1 * time.Hour)}, nil
			},
		}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{Upgrade: "if_7d_since_last"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		joined := strings.Join(res.Details, "\n")
		if !strings.Contains(joined, "skipped") {
			t.Fatalf("expected 'skipped' in details for recent since_last, got: %s", joined)
		}
	})

	t.Run("since_last: runs when threshold exceeded", func(t *testing.T) {
		rt := packagesRuntimeStub{
			stat: func(string) (os.FileInfo, error) {
				return fakeFileInfo{mtime: time.Now().Add(-8 * 24 * time.Hour)}, nil
			},
		}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{Upgrade: "if_7d_since_last"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		joined := strings.Join(res.Details, "\n")
		if !strings.Contains(joined, "last ran") {
			t.Fatalf("expected 'last ran' in details for elapsed since_last, got: %s", joined)
		}
	})

	t.Run("preview errors", func(t *testing.T) {
		rt := packagesRuntimeStub{
			upgradeErr: errors.New("uerr"),
			installErr: errors.New("ierr"),
			autoErr:    errors.New("aerr"),
		}
		res, err := Plan(pluginapi.Context{Host: rt}, &Spec{Upgrade: "always", Install: []string{"x"}, Autoremove: "always"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		joined := strings.Join(res.Details, "\n")
		for _, want := range []string{"failed to preview upgrades", "failed to preview dependency installs", "failed to preview packages to be removed"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected detail %q, got %s", want, joined)
			}
		}
	})
}

func TestCaptureAndSnapshot(t *testing.T) {
	t.Run("missing spec", func(t *testing.T) {
		_, err := Capture(pluginapi.Context{}, "p", nil)
		if err == nil || !strings.Contains(err.Error(), "packages spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
	})

	t.Run("query error", func(t *testing.T) {
		_, err := Capture(pluginapi.Context{Host: packagesRuntimeStub{
			runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") },
		}}, "p", &Spec{Install: []string{"x"}})
		if err == nil || !strings.Contains(err.Error(), "capture package state") {
			t.Fatalf("expected query error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		var seen []string
		rec, err := Capture(pluginapi.Context{Host: packagesRuntimeStub{
			runRootWithOutput: func(cmd string) (string, error) {
				seen = append(seen, cmd)
				if strings.Contains(cmd, "curl") {
					return "install ok installed\t1.0", nil
				}
				return "", nil
			},
		}}, "p", &Spec{
			Update:     "always",
			Upgrade:    "always",
			Autoremove: "always",
			Install:    []string{"curl"},
			Purge:      []string{"vim"},
		})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != pluginapi.ModeBestEffort {
			t.Fatalf("expected best-effort rollback mode, got %q", rec.RollbackMode)
		}
		if len(rec.Objects) != 2 {
			t.Fatalf("expected 2 package objects, got %d", len(rec.Objects))
		}
		if !strings.Contains(strings.Join(seen, "\n"), `-f='${Status}\t${Version}'`) {
			t.Fatalf("expected dpkg-query format string, got %q", seen)
		}

		states := map[string]pluginapi.PackageState{}
		for _, object := range rec.Objects {
			if object.Package == nil {
				t.Fatalf("expected package object, got %+v", object)
			}
			states[object.Package.Name] = *object.Package
		}
		if !states["curl"].WasInstalled || states["curl"].Version != "1.0" || !states["curl"].RequestedInstall {
			t.Fatalf("unexpected curl state: %+v", states["curl"])
		}
		if states["vim"].WasInstalled || states["vim"].Version != "" || !states["vim"].RequestedPurge {
			t.Fatalf("unexpected vim state: %+v", states["vim"])
		}

		joinedNotes := strings.Join(rec.Notes, " | ")
		for _, want := range []string{"apt update is not directly reversible", "apt upgrade rollback is best-effort", "apt autoremove rollback is best-effort"} {
			if !strings.Contains(joinedNotes, want) {
				t.Fatalf("expected note %q, got %q", want, joinedNotes)
			}
		}
	})

	t.Run("notes absent when mode is never", func(t *testing.T) {
		rec, err := Capture(pluginapi.Context{Host: packagesRuntimeStub{
			runRootWithOutput: func(string) (string, error) { return "", nil },
		}}, "p", &Spec{
			Update:     "never",
			Upgrade:    "",
			Autoremove: "never",
			Install:    []string{"curl"},
		})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if len(rec.Notes) != 0 {
			t.Fatalf("expected no notes when all modes are never/empty, got: %v", rec.Notes)
		}
	})

	t.Run("inSet helper", func(t *testing.T) {
		if inSet(map[string]struct{}{"x": {}}, "x") != true {
			t.Fatal("expected x to exist in set")
		}
		if inSet(map[string]struct{}{"x": {}}, "y") != false {
			t.Fatal("expected y to be missing in set")
		}
	})
}

func TestPackagesWouldChange(t *testing.T) {
	t.Run("purge: installed → returns true", func(t *testing.T) {
		rt := packagesRuntimeStub{installed: map[string]bool{"vim": true}}
		if !packagesWouldChange(rt, &Spec{Purge: []string{"vim"}}) {
			t.Fatal("expected packagesWouldChange=true when purge package is installed")
		}
	})

	t.Run("purge: not installed → returns false", func(t *testing.T) {
		if packagesWouldChange(packagesRuntimeStub{}, &Spec{Purge: []string{"vim"}}) {
			t.Fatal("expected packagesWouldChange=false when purge package is not installed")
		}
	})
}

func TestFormatElapsed(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{14 * 24 * time.Hour, "2w"},
		{7 * 24 * time.Hour, "1w"},
		{3 * 24 * time.Hour, "3d"},
		{25 * time.Hour, "1d"},
		{3 * time.Hour, "3h"},
		{45 * time.Minute, "45m"},
	}
	for _, tc := range cases {
		got := formatElapsed(tc.d)
		if got != tc.want {
			t.Errorf("formatElapsed(%v): got %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestValidateOpMode(t *testing.T) {
	valid := []string{"", "never", "always", "once", "if_7d_since_last", "if_12h_since_last", "if_2w_since_last"}
	for _, v := range valid {
		if err := validateOpMode("upgrade", v); err != nil {
			t.Errorf("validateOpMode(%q): unexpected error: %v", v, err)
		}
	}
	invalid := []string{"yes", "true", "if_d_since_last", "if_0d_since_last", "if_7x_since_last", "1d"}
	for _, v := range invalid {
		if err := validateOpMode("upgrade", v); err == nil {
			t.Errorf("validateOpMode(%q): expected error, got nil", v)
		}
	}
}

func TestRuntimePreviewHelpers(t *testing.T) {
	t.Run("nil runtime", func(t *testing.T) {
		if packageInstalled(nil, "curl") {
			t.Fatal("expected packageInstalled(nil) to be false")
		}
		if out, err := aptUpgradePreview(nil); err != nil || len(out) != 0 {
			t.Fatalf("expected nil upgrade preview to be empty, got out=%v err=%v", out, err)
		}
		if out, err := aptInstallPreview(nil, []string{"curl"}); err != nil || len(out) != 0 {
			t.Fatalf("expected nil install preview to be empty, got out=%v err=%v", out, err)
		}
		if out, err := aptInstallPreview(packagesRuntimeStub{}, nil); err != nil || len(out) != 0 {
			t.Fatalf("expected empty install preview to be empty, got out=%v err=%v", out, err)
		}
		if out, err := aptAutoremovePreview(nil); err != nil || len(out) != 0 {
			t.Fatalf("expected nil autoremove preview to be empty, got out=%v err=%v", out, err)
		}
	})

	t.Run("parsing and dedupe", func(t *testing.T) {
		rt := packagesRuntimeStub{
			installed: map[string]bool{"curl": true},
			upgrade:   []string{"openssl", "openssl"},
			install:   []string{"curl", "jq", "jq"},
			auto:      []string{"oldpkg", "oldpkg"},
		}

		if !packageInstalled(rt, "curl") {
			t.Fatal("expected curl to be installed")
		}
		up, err := aptUpgradePreview(rt)
		if err != nil || strings.Join(up, ",") != "openssl" {
			t.Fatalf("unexpected upgrade preview: out=%v err=%v", up, err)
		}
		install, err := aptInstallPreview(rt, []string{"curl", "jq"})
		if err != nil || strings.Join(install, ",") != "curl,jq" {
			t.Fatalf("unexpected install preview: out=%v err=%v", install, err)
		}
		auto, err := aptAutoremovePreview(rt)
		if err != nil || strings.Join(auto, ",") != "oldpkg" {
			t.Fatalf("unexpected autoremove preview: out=%v err=%v", auto, err)
		}
	})
}

type packagesRuntimeStub struct {
	installed map[string]bool
	upgrade   []string
	install   []string
	auto      []string

	upgradeErr        error
	installErr        error
	autoErr           error
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	stat              func(string) (os.FileInfo, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s packagesRuntimeStub) RunRoot(cmd string) error {
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	if strings.HasPrefix(cmd, "dpkg -s ") {
		name := strings.TrimSuffix(strings.TrimPrefix(cmd, "dpkg -s "), " >/dev/null 2>&1")
		name = strings.Trim(name, "\"'")
		if s.installed[name] {
			return nil
		}
		return errors.New("not installed")
	}
	return nil
}

func (s packagesRuntimeStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return "", s.RunRoot(cmd)
}

func (s packagesRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput != nil {
		return s.runRootWithOutput(cmd)
	}
	switch {
	case strings.Contains(cmd, "apt-get -s upgrade"):
		if s.upgradeErr != nil {
			return "", s.upgradeErr
		}
		return joinInstLines(s.upgrade), nil
	case strings.Contains(cmd, "apt-get -s install"):
		if s.installErr != nil {
			return "", s.installErr
		}
		return joinInstLines(s.install), nil
	case strings.Contains(cmd, "apt-get -s autoremove"):
		if s.autoErr != nil {
			return "", s.autoErr
		}
		return joinRemvLines(s.auto), nil
	default:
		return "", nil
	}
}

func (s packagesRuntimeStub) Stat(path string) (os.FileInfo, error) {
	if s.stat != nil {
		return s.stat(path)
	}
	return nil, errors.New("not found")
}

func (s packagesRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }

func (s packagesRuntimeStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile != nil {
		return s.writeRootFile(path, data, mode)
	}
	return nil
}

func joinInstLines(pkgs []string) string {
	var lines []string
	for _, pkg := range pkgs {
		lines = append(lines, "Inst "+pkg)
	}
	return strings.Join(lines, "\n")
}

func joinRemvLines(pkgs []string) string {
	var lines []string
	for _, pkg := range pkgs {
		lines = append(lines, "Remv "+pkg)
	}
	return strings.Join(lines, "\n")
}

func TestCheckAptLock(t *testing.T) {
	prev := checkAptLock
	defer func() { checkAptLock = prev }()

	t.Run("no lock held", func(t *testing.T) {
		checkAptLock = defaultCheckAptLock
		host := packagesRuntimeStub{
			runRootWithOutput: func(cmd string) (string, error) {
				return "", nil
			},
		}
		if err := checkAptLock(host); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("lock held", func(t *testing.T) {
		checkAptLock = defaultCheckAptLock
		host := packagesRuntimeStub{
			runRootWithOutput: func(cmd string) (string, error) {
				return "12345", nil
			},
		}
		err := checkAptLock(host)
		if err == nil || !strings.Contains(err.Error(), "lock is held") {
			t.Fatalf("expected lock-held error, got %v", err)
		}
	})

	t.Run("apply blocked by lock", func(t *testing.T) {
		checkAptLock = func(_ pluginapi.Host) error {
			return fmt.Errorf("apt/dpkg lock is held")
		}
		err := Apply(pluginapi.Context{Host: packagesRuntimeStub{}}, &Spec{Update: "always"})
		if err == nil || !strings.Contains(err.Error(), "lock is held") {
			t.Fatalf("expected apt lock error in Apply, got %v", err)
		}
	})
}

type fakeFileInfo struct {
	mtime time.Time
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o644 }
func (f fakeFileInfo) ModTime() time.Time { return f.mtime }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }
