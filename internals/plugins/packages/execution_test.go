package packages

import (
	"errors"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"os"
	"strings"
	"testing"
)

func TestApply(t *testing.T) {
	t.Run("success runs commands in order", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{Host: packagesRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{
			Update:     true,
			Upgrade:    true,
			Install:    []string{"a", "b"},
			Purge:      []string{"c"},
			Autoremove: true,
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		want := []string{
			"apt-get update -y",
			"apt-get upgrade -y",
			"apt-get install -y a b",
			"apt-get purge -y c",
			"apt-get autoremove -y",
		}
		if strings.Join(cmds, "|") != strings.Join(want, "|") {
			t.Fatalf("unexpected command sequence: got=%v want=%v", cmds, want)
		}
	})

	tests := []struct {
		name    string
		spec    Spec
		failCmd string
		wantSub string
	}{
		{name: "update error", spec: Spec{Update: true}, failCmd: "apt-get update -y", wantSub: "apt-get update failed"},
		{name: "upgrade error", spec: Spec{Upgrade: true}, failCmd: "apt-get upgrade -y", wantSub: "apt-get upgrade failed"},
		{name: "install error", spec: Spec{Install: []string{"x"}}, failCmd: "apt-get install -y x", wantSub: "apt-get install failed"},
		{name: "purge error", spec: Spec{Purge: []string{"x"}}, failCmd: "apt-get purge -y x", wantSub: "apt-get purge failed"},
		{name: "autoremove error", spec: Spec{Autoremove: true}, failCmd: "apt-get autoremove -y", wantSub: "apt-get autoremove failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Apply(pluginapi.ApplyContext{Host: packagesRuntimeStub{
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
	t.Run("rich change path", func(t *testing.T) {
		rt := packagesRuntimeStub{
			installed: map[string]bool{"a": true, "c": true},
			upgrade:   []string{"openssl"},
			install:   []string{"a", "b", "dep1"},
			auto:      []string{"oldpkg"},
		}
		res, err := Plan(pluginapi.PlanContext{Host: rt}, &Spec{
			Update:     true,
			Upgrade:    true,
			Install:    []string{"a", "b"},
			Purge:      []string{"c", "d"},
			Autoremove: true,
		})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.Noop != 2 {
			t.Fatalf("expected noop=2 for changed plan, got %d", res.Noop)
		}
		if !strings.Contains(res.Summary, "update package index") || !strings.Contains(res.Summary, "upgrade") {
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
		res, err := Plan(pluginapi.PlanContext{Host: packagesRuntimeStub{}}, &Spec{})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.Noop != 0 || !strings.Contains(res.Summary, "no-op") {
			t.Fatalf("expected noop summary, got %+v", res)
		}
		if len(res.Diff) != 0 {
			t.Fatalf("expected noop plan to have no diff, got %+v", res.Diff)
		}
	})

	t.Run("update only partial noop", func(t *testing.T) {
		res, err := Plan(pluginapi.PlanContext{Host: packagesRuntimeStub{}}, &Spec{Update: true, Upgrade: true, Autoremove: true})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.Noop != 1 {
			t.Fatalf("expected noop=1, got %d", res.Noop)
		}
		if !strings.Contains(res.Summary, "may change after update") {
			t.Fatalf("unexpected partial noop summary: %q", res.Summary)
		}
	})

	t.Run("preview errors", func(t *testing.T) {
		rt := packagesRuntimeStub{
			upgradeErr: errors.New("uerr"),
			installErr: errors.New("ierr"),
			autoErr:    errors.New("aerr"),
		}
		res, err := Plan(pluginapi.PlanContext{Host: rt}, &Spec{Upgrade: true, Install: []string{"x"}, Autoremove: true})
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
		_, err := Capture(pluginapi.CaptureContext{}, "p", nil)
		if err == nil || !strings.Contains(err.Error(), "packages spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
	})

	t.Run("query error", func(t *testing.T) {
		_, err := Capture(pluginapi.CaptureContext{Host: packagesRuntimeStub{
			runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") },
		}}, "p", &Spec{Install: []string{"x"}})
		if err == nil || !strings.Contains(err.Error(), "capture package state") {
			t.Fatalf("expected query error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		rec, err := Capture(pluginapi.CaptureContext{Host: packagesRuntimeStub{
			runRootWithOutput: func(cmd string) (string, error) {
				if strings.Contains(cmd, "curl") {
					return "install ok installed\t1.0", nil
				}
				return "", nil
			},
		}}, "p", &Spec{
			Update:     true,
			Upgrade:    true,
			Autoremove: true,
			Install:    []string{"curl"},
			Purge:      []string{"vim"},
		})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != rollback.ModeBestEffort {
			t.Fatalf("expected best-effort rollback mode, got %q", rec.RollbackMode)
		}
		if len(rec.Objects) != 2 {
			t.Fatalf("expected 2 package objects, got %d", len(rec.Objects))
		}
		joinedNotes := strings.Join(rec.Notes, " | ")
		for _, want := range []string{"apt update is not directly reversible", "apt upgrade rollback is best-effort", "apt autoremove rollback is best-effort"} {
			if !strings.Contains(joinedNotes, want) {
				t.Fatalf("expected note %q, got %q", want, joinedNotes)
			}
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
}

func (s packagesRuntimeStub) RunRoot(cmd string) error {
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	if strings.HasPrefix(cmd, "dpkg -s ") {
		name := strings.TrimSuffix(strings.TrimPrefix(cmd, "dpkg -s "), " >/dev/null 2>&1")
		name = strings.Trim(name, "\"")
		if s.installed[name] {
			return nil
		}
		return errors.New("not installed")
	}
	return nil
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

func (packagesRuntimeStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (packagesRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }

func (packagesRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

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
