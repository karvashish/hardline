package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestRestoreServiceState(t *testing.T) {
	t.Run("empty unit", func(t *testing.T) {
		err := restoreServiceState(serviceRuntimeStub{}, pluginapi.ServiceState{Known: true})
		if err == nil || !strings.Contains(err.Error(), "service unit is empty") {
			t.Fatalf("expected empty unit error, got %v", err)
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		err := restoreServiceState(serviceRuntimeStub{}, pluginapi.ServiceState{Unit: "ssh", Known: false})
		if err == nil || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("expected unknown state error, got %v", err)
		}
	})

	t.Run("enabled and stopped", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }, runRootWithOutput: knownUnit}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, EnabledState: "enabled", Active: false, ActiveState: "inactive"}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("active restarts", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }, runRootWithOutput: knownUnit}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "restart") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("disable when not enabled", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }, runRootWithOutput: knownUnit}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: false, EnabledState: "disabled", Active: false, ActiveState: "inactive"}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "disable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("absent unit skipped", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{
			runRoot:           func(cmd string) error { cmds = append(cmds, cmd); return nil },
			runRootWithOutput: func(string) (string, error) { return "", nil },
		}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "auditd", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}); err != nil {
			t.Fatalf("expected nil for absent unit, got %v", err)
		}
		if len(cmds) != 0 {
			t.Fatalf("expected no restore commands for absent unit, got %#v", cmds)
		}
	})

	t.Run("enable error", func(t *testing.T) {
		host := serviceRuntimeStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "enable") {
				return errors.New("enable boom")
			}
			return nil
		}, runRootWithOutput: knownUnit}
		err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"})
		if err == nil || !strings.Contains(err.Error(), "enabled state") {
			t.Fatalf("expected enabled state error, got %v", err)
		}
	})

	t.Run("active error", func(t *testing.T) {
		host := serviceRuntimeStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "restart") || strings.Contains(cmd, "stop") {
				return errors.New("active boom")
			}
			return nil
		}, runRootWithOutput: knownUnit}
		err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: false, EnabledState: "disabled", Active: true, ActiveState: "active"})
		if err == nil || !strings.Contains(err.Error(), "active state") {
			t.Fatalf("expected active state error, got %v", err)
		}
	})
}

func knownUnit(cmd string) (string, error) {
	if strings.Contains(cmd, "is-enabled") {
		return "enabled\n", nil
	}
	return "active\n", nil
}

func TestSnapshotServiceState(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		_, err := snapshotServiceState(nil, "ssh")
		if err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host-required error, got %v", err)
		}
	})

	t.Run("known state", func(t *testing.T) {
		host := serviceRuntimeStub{runRootWithOutput: func(cmd string) (string, error) {
			if strings.Contains(cmd, "is-enabled") {
				return "enabled\n", nil
			}
			return "active\n", nil
		}}
		state, err := snapshotServiceState(host, "ssh")
		if err != nil {
			t.Fatalf("snapshotServiceState failed: %v", err)
		}
		if !state.Enabled || !state.Active || !state.Known || state.Unit != "ssh" {
			t.Fatalf("unexpected state: %+v", state)
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		host := serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "\n", nil }}
		state, err := snapshotServiceState(host, "ssh")
		if err != nil {
			t.Fatalf("snapshotServiceState failed: %v", err)
		}
		if state.Known {
			t.Fatalf("expected unknown state, got %+v", state)
		}
	})

	t.Run("enabled query error", func(t *testing.T) {
		host := serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("enabled boom") }}
		if _, err := snapshotServiceState(host, "ssh"); err == nil || !strings.Contains(err.Error(), "enabled boom") {
			t.Fatalf("expected enabled query error, got %v", err)
		}
	})

	t.Run("active query error", func(t *testing.T) {
		host := serviceRuntimeStub{runRootWithOutput: func(cmd string) (string, error) {
			if strings.Contains(cmd, "is-enabled") {
				return "enabled", nil
			}
			return "", errors.New("active boom")
		}}
		if _, err := snapshotServiceState(host, "ssh"); err == nil || !strings.Contains(err.Error(), "active boom") {
			t.Fatalf("expected active query error, got %v", err)
		}
	})
}

func TestServiceStateConflict(t *testing.T) {
	t.Run("unknown skipped", func(t *testing.T) {
		if got := serviceStateConflict(serviceRuntimeStub{}, pluginapi.ServiceState{Unit: "nginx", Known: false}); got != nil {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("empty unit skipped", func(t *testing.T) {
		if got := serviceStateConflict(serviceRuntimeStub{}, pluginapi.ServiceState{Known: true}); got != nil {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("matching state", func(t *testing.T) {
		host := stateStub("enabled", "active")
		if got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("enabled differs", func(t *testing.T) {
		host := stateStub("disabled", "active")
		got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"})
		if len(got) != 1 || !strings.Contains(got[0], "enabled state") {
			t.Fatalf("expected enabled-state conflict, got %v", got)
		}
	})

	t.Run("active differs", func(t *testing.T) {
		host := stateStub("enabled", "inactive")
		got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"})
		if len(got) != 1 || !strings.Contains(got[0], "active state") {
			t.Fatalf("expected active-state conflict, got %v", got)
		}
	})

	t.Run("static unit no false conflict", func(t *testing.T) {
		host := stateStub("static", "active")
		if got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "systemd-journald", Known: true, Enabled: false, EnabledState: "disabled", Active: true, ActiveState: "active"}); len(got) != 0 {
			t.Fatalf("expected no conflicts for static unit, got %v", got)
		}
	})

	t.Run("snapshot error skipped", func(t *testing.T) {
		host := serviceRuntimeStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
		if got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}); got != nil {
			t.Fatalf("expected nil on snapshot error, got %v", got)
		}
	})
}

func stateStub(enabled, active string) serviceRuntimeStub {
	return serviceRuntimeStub{runRootWithOutput: func(cmd string) (string, error) {
		if strings.Contains(cmd, "is-enabled") {
			return enabled + "\n", nil
		}
		return active + "\n", nil
	}}
}

func TestServicePluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(serviceRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "missing service snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := plugin.Rollback(serviceRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile})
		if err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})

	t.Run("service rolled back", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }, runRootWithOutput: knownUnit}
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}}
		if err := plugin.Rollback(host, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands, got %#v", cmds)
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		host := stateStub("disabled", "active")
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, EnabledState: "enabled", Active: true, ActiveState: "active"}}
		if got := plugin.DetectConflict(host, obj); len(got) != 1 {
			t.Fatalf("expected one conflict, got %v", got)
		}
		if got := plugin.DetectConflict(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); got != nil {
			t.Fatalf("expected nil for non-service kind, got %v", got)
		}
	})
}
