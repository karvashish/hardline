package service

import (
	"errors"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"golang.org/x/crypto/ssh"
	"os"
	"strings"
	"testing"
)

func TestApply(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "service name is required") {
			t.Fatalf("expected missing name error, got %v", err)
		}
	})

	t.Run("enable and restart when dirty", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "sshd", State: "restart", Enabled: boolPtr(true)}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				if cmd == "systemctl is-enabled ssh >/dev/null 2>&1" {
					return errors.New("disabled")
				}
				if cmd == "systemctl is-active ssh >/dev/null 2>&1" {
					return nil
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		for _, want := range []string{"systemctl enable ssh", "systemctl restart ssh"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected command %q, got %v", want, cmds)
			}
		}
	})

	t.Run("disable and stop", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "stop", Enabled: boolPtr(false)}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		for _, want := range []string{"systemctl disable cron", "systemctl stop cron"} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected command %q, got %v", want, cmds)
			}
		}
	})

	t.Run("restart always runs", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "restart"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "systemctl restart cron") {
			t.Fatalf("restart should have run: %v", cmds)
		}
	})

	t.Run("reload always runs", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "reload"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), "systemctl reload-or-restart cron") {
			t.Fatalf("reload-or-restart should have run: %v", cmds)
		}
	})

	t.Run("start skips when already active", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "start"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), "systemctl start cron") {
			t.Fatalf("start should have been skipped: %v", cmds)
		}
	})

	t.Run("stop skips when inactive", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "stop"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				cmds = append(cmds, cmd)
				if cmd == "systemctl is-active cron >/dev/null 2>&1" {
					return errors.New("inactive")
				}
				return nil
			},
		})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), "systemctl stop cron") {
			t.Fatalf("stop should have been skipped: %v", cmds)
		}
	})

	t.Run("unsupported state", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "wat"}, ApplyDeps{})
		if err == nil || !strings.Contains(err.Error(), "unsupported service state") {
			t.Fatalf("expected unsupported state error, got %v", err)
		}
	})

	t.Run("enable command error", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", Enabled: boolPtr(true)}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				if cmd == "systemctl is-enabled cron >/dev/null 2>&1" {
					return errors.New("disabled")
				}
				return errors.New("boom")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "enable/disable") {
			t.Fatalf("expected enable/disable error, got %v", err)
		}
	})

	t.Run("state command error", func(t *testing.T) {
		err := Apply(pluginapi.ApplyContext{}, &Spec{Name: "cron", State: "start"}, ApplyDeps{
			RunRoot: func(_ *ssh.Client, cmd string) error {
				if cmd == "systemctl is-active cron >/dev/null 2>&1" {
					return errors.New("inactive")
				}
				return errors.New("boom")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "systemctl start") {
			t.Fatalf("expected state command error, got %v", err)
		}
	})
}

func TestPlan(t *testing.T) {
	_, err := Plan(pluginapi.PlanContext{Runtime: serviceRuntimeStub{}}, &Spec{})
	if err == nil || !strings.Contains(err.Error(), "service name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}

	res, err := Plan(pluginapi.PlanContext{Runtime: serviceRuntimeStub{enabled: map[string]bool{"ssh": true}, active: map[string]bool{"ssh": true}}}, &Spec{Name: "sshd", Enabled: boolPtr(true), State: "restart"})
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if !strings.Contains(res.Summary, "restart ssh") {
		t.Fatalf("unexpected plan summary: %q", res.Summary)
	}
	if len(res.Details) == 0 {
		t.Fatal("expected plan details")
	}

	cases := []struct {
		name       string
		spec       Spec
		wantSubstr string
	}{
		{name: "empty state", spec: Spec{Name: "cron"}, wantSubstr: "no-op"},
		{name: "started", spec: Spec{Name: "cron", State: "started"}, wantSubstr: "started"},
		{name: "stopped", spec: Spec{Name: "cron", State: "stopped"}, wantSubstr: "stopped"},
		{name: "reloaded", spec: Spec{Name: "cron", State: "reloaded"}, wantSubstr: "reload or restart"},
		{name: "unsupported", spec: Spec{Name: "cron", State: "broken"}, wantSubstr: "unsupported state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Plan(pluginapi.PlanContext{Runtime: serviceRuntimeStub{}}, &tc.spec)
			if err != nil {
				t.Fatalf("Plan failed: %v", err)
			}
			if !strings.Contains(out.Summary, tc.wantSubstr) {
				t.Fatalf("expected summary to contain %q, got %q", tc.wantSubstr, out.Summary)
			}
		})
	}
}

func TestCaptureRollback(t *testing.T) {
	t.Run("missing spec", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, "s", nil, RollbackDeps{})
		if err == nil || !strings.Contains(err.Error(), "service spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
	})

	t.Run("query error", func(t *testing.T) {
		_, err := CaptureRollback(pluginapi.RollbackContext{}, "s", &Spec{Name: "sshd"}, RollbackDeps{
			RunRootWithOutput: func(*ssh.Client, string) (string, error) { return "", errors.New("boom") },
		})
		if err == nil || !strings.Contains(err.Error(), "capture service snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		calls := 0
		rec, err := CaptureRollback(pluginapi.RollbackContext{}, "s", &Spec{Name: "sshd"}, RollbackDeps{
			RunRootWithOutput: func(*ssh.Client, string) (string, error) {
				calls++
				if calls == 1 {
					return "enabled", nil
				}
				return "active", nil
			},
		})
		if err != nil {
			t.Fatalf("CaptureRollback failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 1 || rec.Objects[0].Service == nil {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
		if rec.Objects[0].Service.Unit != "ssh" {
			t.Fatalf("expected ssh unit normalization, got %+v", rec.Objects[0].Service)
		}
	})
}

func TestUnitAndStateHelpers(t *testing.T) {
	if got := normalizeServiceUnit("sshd"); got != "ssh" {
		t.Fatalf("expected sshd -> ssh, got %q", got)
	}
	if got := normalizeServiceUnit(" cron "); got != "cron" {
		t.Fatalf("expected trim, got %q", got)
	}

	if !serviceIsEnabled(nil, "x", func(*ssh.Client, string) error { return nil }) {
		t.Fatal("expected enabled=true")
	}
	if serviceIsEnabled(nil, "x", func(*ssh.Client, string) error { return errors.New("no") }) {
		t.Fatal("expected enabled=false")
	}
	if !serviceIsActive(nil, "x", func(*ssh.Client, string) error { return nil }) {
		t.Fatal("expected active=true")
	}
	if serviceIsActive(nil, "x", func(*ssh.Client, string) error { return errors.New("no") }) {
		t.Fatal("expected active=false")
	}
}

func boolPtr(v bool) *bool { return &v }

type serviceRuntimeStub struct {
	enabled map[string]bool
	active  map[string]bool
}

func (s serviceRuntimeStub) RunRoot(cmd string) error {
	switch {
	case strings.HasPrefix(cmd, "systemctl is-enabled "):
		unit := strings.TrimSuffix(strings.TrimPrefix(cmd, "systemctl is-enabled "), " >/dev/null 2>&1")
		if s.enabled[unit] {
			return nil
		}
		return errors.New("disabled")
	case strings.HasPrefix(cmd, "systemctl is-active "):
		unit := strings.TrimSuffix(strings.TrimPrefix(cmd, "systemctl is-active "), " >/dev/null 2>&1")
		if s.active[unit] {
			return nil
		}
		return errors.New("inactive")
	default:
		return nil
	}
}

func (serviceRuntimeStub) RunRootWithOutput(string) (string, error) { return "", nil }

func (serviceRuntimeStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (serviceRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }
