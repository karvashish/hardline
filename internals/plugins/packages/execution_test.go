package packages

import (
	"errors"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
	"os"
	"strings"
	"testing"
)

func TestApply(t *testing.T) {
	t.Run("success runs commands in order", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &profile.PackageSpec{
			Update:     true,
			Upgrade:    true,
			Install:    []string{"a", "b"},
			Purge:      []string{"c"},
			Autoremove: true,
		}, ApplyDeps{RunRoot: func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}})
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
		spec    profile.PackageSpec
		failCmd string
		wantSub string
	}{
		{name: "update error", spec: profile.PackageSpec{Update: true}, failCmd: "apt-get update -y", wantSub: "apt-get update failed"},
		{name: "upgrade error", spec: profile.PackageSpec{Upgrade: true}, failCmd: "apt-get upgrade -y", wantSub: "apt-get upgrade failed"},
		{name: "install error", spec: profile.PackageSpec{Install: []string{"x"}}, failCmd: "apt-get install -y x", wantSub: "apt-get install failed"},
		{name: "purge error", spec: profile.PackageSpec{Purge: []string{"x"}}, failCmd: "apt-get purge -y x", wantSub: "apt-get purge failed"},
		{name: "autoremove error", spec: profile.PackageSpec{Autoremove: true}, failCmd: "apt-get autoremove -y", wantSub: "apt-get autoremove failed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Apply(pluginapi.ApplyContext{}, &tc.spec, ApplyDeps{RunRoot: func(_ *ssh.Client, cmd string) error {
				if cmd == tc.failCmd {
					return errors.New("boom")
				}
				return nil
			}})
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q error, got %v", tc.wantSub, err)
			}
		})
	}
}

func TestPlan(t *testing.T) {
	t.Run("rich change path", func(t *testing.T) {
		insp := packagesInspectorStub{
			installed: map[string]bool{"a": true, "c": true},
			upgrade:   []string{"openssl"},
			install:   []string{"a", "b", "dep1"},
			auto:      []string{"oldpkg"},
		}
		res, err := Plan(pluginapi.PlanContext{Inspector: insp}, &profile.PackageSpec{
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
	})

	t.Run("full noop", func(t *testing.T) {
		res, err := Plan(pluginapi.PlanContext{Inspector: packagesInspectorStub{}}, &profile.PackageSpec{})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.Noop != 0 || !strings.Contains(res.Summary, "no-op") {
			t.Fatalf("expected noop summary, got %+v", res)
		}
	})

	t.Run("update only partial noop", func(t *testing.T) {
		res, err := Plan(pluginapi.PlanContext{Inspector: packagesInspectorStub{}}, &profile.PackageSpec{Update: true, Upgrade: true, Autoremove: true})
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
		insp := packagesInspectorStub{
			upgradeErr: errors.New("uerr"),
			installErr: errors.New("ierr"),
			autoErr:    errors.New("aerr"),
		}
		res, err := Plan(pluginapi.PlanContext{Inspector: insp}, &profile.PackageSpec{Upgrade: true, Install: []string{"x"}, Autoremove: true})
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

func TestCaptureRollbackAndSnapshot(t *testing.T) {
	t.Run("missing spec", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "p", Type: "packages"}, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "packages spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
	})

	t.Run("query error", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{ID: "p", Type: "packages", Packages: &profile.PackageSpec{Install: []string{"x"}}}, RollbackDeps{
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "capture package state") {
			t.Fatalf("expected query error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		rec, err := CaptureRollback(pluginapi.RollbackContext{}, profile.Step{
			ID:   "p",
			Type: "packages",
			Packages: &profile.PackageSpec{
				Update:     true,
				Upgrade:    true,
				Autoremove: true,
				Install:    []string{"curl"},
				Purge:      []string{"vim"},
			},
		}, RollbackDeps{
			RunRootWithOutput: func(_ *ssh.Client, cmd string) (string, error) {
				if strings.Contains(cmd, "curl") {
					return "install ok installed\t1.0", nil
				}
				return "", nil
			},
		})
		if err != nil {
			t.Fatalf("CaptureRollback failed: %v", err)
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

type packagesInspectorStub struct {
	installed map[string]bool
	upgrade   []string
	install   []string
	auto      []string

	upgradeErr error
	installErr error
	autoErr    error
}

func (s packagesInspectorStub) PackageInstalled(name string) bool {
	return s.installed[name]
}

func (s packagesInspectorStub) AptAutoremovePreview() ([]string, error) {
	if s.autoErr != nil {
		return nil, s.autoErr
	}
	return append([]string(nil), s.auto...), nil
}

func (s packagesInspectorStub) AptUpgradePreview() ([]string, error) {
	if s.upgradeErr != nil {
		return nil, s.upgradeErr
	}
	return append([]string(nil), s.upgrade...), nil
}

func (s packagesInspectorStub) AptInstallPreview([]string) ([]string, error) {
	if s.installErr != nil {
		return nil, s.installErr
	}
	return append([]string(nil), s.install...), nil
}

func (s packagesInspectorStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (s packagesInspectorStub) ReadRootFile(string) (string, error) { return "", nil }

func (s packagesInspectorStub) IsServiceEnabled(string) bool { return false }

func (s packagesInspectorStub) IsServiceActive(string) bool { return false }

func (s packagesInspectorStub) SSHIncludePresent() bool { return false }

func (s packagesInspectorStub) SSHConfigTest() error { return nil }

func (s packagesInspectorStub) FirewallIncludePresent() bool { return false }

func (s packagesInspectorStub) FirewallConfigTest() error { return nil }

func (s packagesInspectorStub) FirewallAllowedPorts() (map[string][]int, error) { return nil, nil }

func (s packagesInspectorStub) FirewallPolicySummary() ([]string, error) { return nil, nil }

func (s packagesInspectorStub) FirewallOtherManagers() ([]string, error) { return nil, nil }

func (s packagesInspectorStub) FirewallOnDiskPolicySummary(string) ([]string, error) { return nil, nil }

func (s packagesInspectorStub) FirewallHasStatefulBaseline() (bool, error) { return false, nil }

func (s packagesInspectorStub) FirewallHasDefaultDropInput() (bool, error) { return false, nil }

func (s packagesInspectorStub) FirewallAllowedPortsDetailed() ([]pluginapi.FirewallRuleInfo, error) {
	return nil, nil
}
