package service

import (
	"errors"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"os"
	"strings"
	"testing"
	"time"
)

func TestApply(t *testing.T) {
	t.Run("missing name", func(t *testing.T) {
		err := Apply(pluginapi.Context{}, &Spec{})
		if err == nil || !strings.Contains(err.Error(), "service name is required") {
			t.Fatalf("expected missing name error, got %v", err)
		}
	})

	// The unit name reaches systemctl verbatim: "sshd" is the real unit on
	// RHEL-family hosts, so the plugin must not rewrite it to Debian's "ssh".
	t.Run("enable and restart when dirty", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				if cmd == `systemctl is-enabled 'sshd' >/dev/null 2>&1` {
					return errors.New("disabled")
				}
				return nil
			},
		}}, &Spec{Name: "sshd", State: "restart", Enabled: boolPtr(true)})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		for _, want := range []string{`systemctl enable 'sshd'`, `systemctl restart 'sshd'`} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected command %q, got %v", want, cmds)
			}
		}
		if strings.Contains(joined, `'ssh'`) {
			t.Fatalf("unit name must not be rewritten, got %v", cmds)
		}
	})

	t.Run("disable and stop", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{Name: "cron", State: "stop", Enabled: boolPtr(false)})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		joined := strings.Join(cmds, "\n")
		for _, want := range []string{`systemctl disable 'cron'`, `systemctl stop 'cron'`} {
			if !strings.Contains(joined, want) {
				t.Fatalf("expected command %q, got %v", want, cmds)
			}
		}
	})

	t.Run("restart always runs", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{Name: "cron", State: "restart"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), `systemctl restart 'cron'`) {
			t.Fatalf("restart should have run: %v", cmds)
		}
	})

	t.Run("reload always runs", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{Name: "cron", State: "reload"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), `systemctl reload-or-restart 'cron'`) {
			t.Fatalf("reload-or-restart should have run: %v", cmds)
		}
	})

	t.Run("restart_policy=on_change skips restart when upstream unchanged and service active", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{
			Host: serviceRuntimeStub{
				runRoot: func(cmd string) error {
					cmds = append(cmds, cmd)
					return nil
				},
			},
			StepChanges: map[string]bool{"tmpl-step": false},
		}, &Spec{Name: "cron", State: "restart", RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl-step"}}})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), `systemctl restart 'cron'`) {
			t.Fatalf("restart should have been skipped: %v", cmds)
		}
	})

	t.Run("restart_policy=on_change runs restart when upstream changed", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{
			Host: serviceRuntimeStub{
				runRoot: func(cmd string) error {
					cmds = append(cmds, cmd)
					return nil
				},
			},
			StepChanges: map[string]bool{"tmpl-step": true},
		}, &Spec{Name: "cron", State: "restart", RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl-step"}}})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), `systemctl restart 'cron'`) {
			t.Fatalf("restart should have run when upstream changed: %v", cmds)
		}
	})

	t.Run("restart_policy=on_change runs restart when service inactive", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{
			Host: serviceRuntimeStub{
				runRoot: func(cmd string) error {
					cmds = append(cmds, cmd)
					if strings.Contains(cmd, "is-active") {
						return errors.New("inactive")
					}
					return nil
				},
			},
			StepChanges: map[string]bool{"tmpl-step": false},
		}, &Spec{Name: "cron", State: "restart", RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl-step"}}})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(strings.Join(cmds, "\n"), `systemctl restart 'cron'`) {
			t.Fatalf("restart should have run when service inactive: %v", cmds)
		}
	})

	t.Run("start skips when already active", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				return nil
			},
		}}, &Spec{Name: "cron", State: "start"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), `systemctl start 'cron'`) {
			t.Fatalf("start should have been skipped: %v", cmds)
		}
	})

	t.Run("stop skips when inactive", func(t *testing.T) {
		var cmds []string
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				if cmd == `systemctl is-active 'cron' >/dev/null 2>&1` {
					return errors.New("inactive")
				}
				return nil
			},
		}}, &Spec{Name: "cron", State: "stop"})
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(strings.Join(cmds, "\n"), `systemctl stop 'cron'`) {
			t.Fatalf("stop should have been skipped: %v", cmds)
		}
	})

	t.Run("unsupported state", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{}}, &Spec{Name: "cron", State: "wat"})
		if err == nil || !strings.Contains(err.Error(), "unsupported service state") {
			t.Fatalf("expected unsupported state error, got %v", err)
		}
	})

	t.Run("enable command error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				if cmd == `systemctl is-enabled 'cron' >/dev/null 2>&1` {
					return errors.New("disabled")
				}
				return errors.New("boom")
			},
		}}, &Spec{Name: "cron", Enabled: boolPtr(true)})
		if err == nil || !strings.Contains(err.Error(), "enable/disable") {
			t.Fatalf("expected enable/disable error, got %v", err)
		}
	})

	t.Run("state command error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: serviceRuntimeStub{
			runRoot: func(cmd string) error {
				if cmd == `systemctl is-active 'cron' >/dev/null 2>&1` {
					return errors.New("inactive")
				}
				return errors.New("boom")
			},
		}}, &Spec{Name: "cron", State: "start"})
		if err == nil || !strings.Contains(err.Error(), "systemctl start") {
			t.Fatalf("expected state command error, got %v", err)
		}
	})
}

func TestPlan(t *testing.T) {
	_, err := Plan(pluginapi.Context{Host: serviceRuntimeStub{}}, &Spec{})
	if err == nil || !strings.Contains(err.Error(), "service name is required") {
		t.Fatalf("expected missing name error, got %v", err)
	}

	res, err := Plan(pluginapi.Context{Host: serviceRuntimeStub{enabled: map[string]bool{"sshd": true}, active: map[string]bool{"sshd": true}}}, &Spec{Name: "sshd", Enabled: boolPtr(true), State: "restart"})
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if !res.WillChange {
		t.Fatalf("expected restart plan to require change, got WillChange=false")
	}
	if !strings.Contains(res.Summary, "restart sshd") {
		t.Fatalf("unexpected plan summary: %q", res.Summary)
	}
	if len(res.Details) == 0 {
		t.Fatal("expected plan details")
	}
	if len(res.Diff) != 1 || !strings.Contains(res.Diff[0], "restart") {
		t.Fatalf("expected restart diff, got %+v", res.Diff)
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
			out, err := Plan(pluginapi.Context{Host: serviceRuntimeStub{}}, &tc.spec)
			if err != nil {
				t.Fatalf("Plan failed: %v", err)
			}
			if tc.name == "empty state" && out.WillChange {
				t.Fatalf("expected empty state to be aligned, got WillChange=true")
			}
			if !strings.Contains(out.Summary, tc.wantSubstr) {
				t.Fatalf("expected summary to contain %q, got %q", tc.wantSubstr, out.Summary)
			}
			if tc.name == "empty state" && len(out.Diff) != 0 {
				t.Fatalf("expected empty state to have no diff, got %+v", out.Diff)
			}
		})
	}
}

func TestPlanRestartPolicy(t *testing.T) {
	t.Run("on_change with upstream unchanged and service active: ALREADY ALIGNED", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{
			Host:        serviceRuntimeStub{active: map[string]bool{"cron": true}, enabled: map[string]bool{"cron": true}},
			StepChanges: map[string]bool{"tmpl": false},
		}, &Spec{Name: "cron", State: "restarted", Enabled: boolPtr(true), RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl"}}})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange {
			t.Fatalf("expected ALREADY ALIGNED, got WillChange=true diff=%v", res.Diff)
		}
	})

	t.Run("restart_policy=on_change with upstream changed: CHANGE PLANNED", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{
			Host:        serviceRuntimeStub{active: map[string]bool{"cron": true}, enabled: map[string]bool{"cron": true}},
			StepChanges: map[string]bool{"tmpl": true},
		}, &Spec{Name: "cron", State: "restarted", Enabled: boolPtr(true), RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl"}}})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected CHANGE PLANNED, got WillChange=false")
		}
	})

	t.Run("restart_policy=on_change with service inactive: CHANGE PLANNED", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{
			Host:        serviceRuntimeStub{active: map[string]bool{}, enabled: map[string]bool{}},
			StepChanges: map[string]bool{"tmpl": false},
		}, &Spec{Name: "cron", State: "restarted", RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"tmpl"}}})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected CHANGE PLANNED when service inactive, got WillChange=false")
		}
	})
}

func TestCapture(t *testing.T) {
	t.Run("missing spec", func(t *testing.T) {
		_, err := Capture(pluginapi.Context{}, "s", nil)
		if err == nil || !strings.Contains(err.Error(), "service spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
	})

	t.Run("query error", func(t *testing.T) {
		_, err := Capture(pluginapi.Context{Host: serviceRuntimeStub{
			runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") },
		}}, "s", &Spec{Name: "sshd"})
		if err == nil || !strings.Contains(err.Error(), "capture service snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		calls := 0
		rec, err := Capture(pluginapi.Context{Host: serviceRuntimeStub{
			runRootWithOutput: func(string) (string, error) {
				calls++
				if calls == 1 {
					return "enabled", nil
				}
				return "active", nil
			},
		}}, "s", &Spec{Name: "sshd"})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 1 || rec.Objects[0].Service == nil {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
		if rec.Objects[0].Service.Unit != "sshd" {
			t.Fatalf("expected the profile's unit name verbatim, got %+v", rec.Objects[0].Service)
		}
		if rec.Reload != nil {
			t.Fatalf("expected nil reload for enable-only step, got %+v", rec.Reload)
		}
	})

	t.Run("records reload intent", func(t *testing.T) {
		calls := 0
		rec, err := Capture(pluginapi.Context{Host: serviceRuntimeStub{
			runRootWithOutput: func(string) (string, error) {
				calls++
				if calls == 1 {
					return "enabled", nil
				}
				return "active", nil
			},
		}}, "s", &Spec{
			Name:          "sshd",
			State:         "Reloaded",
			RestartPolicy: &RestartPolicy{Type: "on_change", Steps: []string{"ssh-template-apply"}},
		})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.Reload == nil {
			t.Fatalf("expected reload intent recorded")
		}
		if rec.Reload.Action != "reloaded" || rec.Reload.RestartPolicy != "on_change" {
			t.Fatalf("unexpected reload record: %+v", rec.Reload)
		}
		if len(rec.Reload.RestartDeps) != 1 || rec.Reload.RestartDeps[0] != "ssh-template-apply" {
			t.Fatalf("unexpected reload deps: %+v", rec.Reload.RestartDeps)
		}
	})
}

func TestUnitAndStateHelpers(t *testing.T) {
	if serviceIsEnabled(nil, "x") {
		t.Fatal("expected nil host to report disabled")
	}
	if !serviceIsEnabled(serviceRuntimeStub{runRoot: func(string) error { return nil }}, "x") {
		t.Fatal("expected enabled=true")
	}
	if serviceIsEnabled(serviceRuntimeStub{runRoot: func(string) error { return errors.New("no") }}, "x") {
		t.Fatal("expected enabled=false")
	}
	if serviceIsActive(nil, "x") {
		t.Fatal("expected nil host to report inactive")
	}
	if !serviceIsActive(serviceRuntimeStub{runRoot: func(string) error { return nil }}, "x") {
		t.Fatal("expected active=true")
	}
	if serviceIsActive(serviceRuntimeStub{runRoot: func(string) error { return errors.New("no") }}, "x") {
		t.Fatal("expected active=false")
	}

	if serviceUnitPresent(nil, "x") {
		t.Fatal("expected nil host to report absent")
	}
	if !serviceUnitPresent(serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "# /lib/systemd/system/x.service\n", nil }}, "x") {
		t.Fatal("expected present=true when systemctl cat returns a fragment")
	}
	if serviceUnitPresent(serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "\n", nil }}, "x") {
		t.Fatal("expected present=false when systemctl cat returns nothing")
	}
	if serviceUnitPresent(serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}, "x") {
		t.Fatal("expected present=false on query error")
	}
}

func boolPtr(v bool) *bool { return &v }

type serviceRuntimeStub struct {
	enabled           map[string]bool
	active            map[string]bool
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
}

func (s serviceRuntimeStub) RunRoot(cmd string) error {
	if s.runRoot != nil {
		return s.runRoot(cmd)
	}
	switch {
	case strings.HasPrefix(cmd, "systemctl is-enabled "):
		unit := strings.TrimSuffix(strings.TrimPrefix(cmd, "systemctl is-enabled "), " >/dev/null 2>&1")
		unit = strings.Trim(unit, `'`)
		if s.enabled[unit] {
			return nil
		}
		return errors.New("disabled")
	case strings.HasPrefix(cmd, "systemctl is-active "):
		unit := strings.TrimSuffix(strings.TrimPrefix(cmd, "systemctl is-active "), " >/dev/null 2>&1")
		unit = strings.Trim(unit, `'`)
		if s.active[unit] {
			return nil
		}
		return errors.New("inactive")
	default:
		return nil
	}
}

func (s serviceRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput != nil {
		return s.runRootWithOutput(cmd)
	}
	return "", nil
}

func (serviceRuntimeStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not found") }

func (serviceRuntimeStub) ReadRootFile(string) (string, error) { return "", nil }

func (serviceRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func (s serviceRuntimeStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

func TestValidateServiceUnit(t *testing.T) {
	for _, unit := range []string{"ssh", "cron", "systemd-timesyncd.service", "getty@tty1.service", "auditd.socket", "apt-daily.timer", "multi-user.target"} {
		if err := validateServiceUnit(unit); err != nil {
			t.Fatalf("expected %q to pass, got %v", unit, err)
		}
	}

	reject := []string{
		"", " ", "ssh ", "ssh\n",
		"ssh$(touch /tmp/hardline-pwn)",
		"ssh`id`",
		"ssh${HOME}",
		"ssh;id", "ssh|id", "ssh&id", "ssh>x", "ssh<x",
		"ssh'x", `ssh"x`, `ssh\x`, "ssh*", "ssh/../x",
		"--force", "-rf", "-",
		strings.Repeat("a", 129),
	}
	for _, unit := range reject {
		if err := validateServiceUnit(unit); err == nil {
			t.Fatalf("expected %q to be rejected", unit)
		}
	}
}

func TestValidateServiceSpecRejectsInjection(t *testing.T) {
	spec := &Spec{Name: "ssh$(touch /tmp/hardline-pwn)", State: "restarted"}
	if err := validateServiceSpec(spec); err == nil {
		t.Fatal("expected hostile unit name to be rejected at the plugin boundary")
	}

	h := serviceRuntimeStub{}
	if _, err := Plan(pluginapi.Context{Host: h}, spec); err == nil {
		t.Fatal("expected Plan to reject a hostile unit name before running any command")
	}
	if err := Apply(pluginapi.Context{Host: h}, spec); err == nil {
		t.Fatal("expected Apply to reject a hostile unit name")
	}
}
