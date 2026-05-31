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
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: false}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("active restarts", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "enable") || !strings.Contains(cmds[1], "restart") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("disable when not enabled", func(t *testing.T) {
		var cmds []string
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		if err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: false, Active: false}); err != nil {
			t.Fatalf("restoreServiceState failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "disable") || !strings.Contains(cmds[1], "stop") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("enable error", func(t *testing.T) {
		host := serviceRuntimeStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "enable") {
				return errors.New("enable boom")
			}
			return nil
		}}
		err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true})
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
		}}
		err := restoreServiceState(host, pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: false, Active: true})
		if err == nil || !strings.Contains(err.Error(), "active state") {
			t.Fatalf("expected active state error, got %v", err)
		}
	})
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
		host := serviceRuntimeStub{enabled: map[string]bool{"nginx": true}, active: map[string]bool{"nginx": true}}
		if got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true}); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("enabled differs", func(t *testing.T) {
		host := serviceRuntimeStub{enabled: map[string]bool{}, active: map[string]bool{"nginx": true}}
		got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true})
		if len(got) != 1 || !strings.Contains(got[0], "enabled state") {
			t.Fatalf("expected enabled-state conflict, got %v", got)
		}
	})

	t.Run("active differs", func(t *testing.T) {
		host := serviceRuntimeStub{enabled: map[string]bool{"nginx": true}, active: map[string]bool{}}
		got := serviceStateConflict(host, pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true})
		if len(got) != 1 || !strings.Contains(got[0], "active state") {
			t.Fatalf("expected active-state conflict, got %v", got)
		}
	})
}

func TestServicePluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(serviceRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "missing service snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := plugin.Rollback(serviceRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop, got %v", err)
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
		host := serviceRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "ssh", Known: true, Enabled: true, Active: true}}
		if err := plugin.Rollback(host, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
		if len(cmds) != 2 {
			t.Fatalf("expected 2 commands, got %#v", cmds)
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		host := serviceRuntimeStub{enabled: map[string]bool{}, active: map[string]bool{"nginx": true}}
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectService, Service: &pluginapi.ServiceState{Unit: "nginx", Known: true, Enabled: true, Active: true}}
		if got := plugin.DetectConflict(host, obj); len(got) != 1 {
			t.Fatalf("expected one conflict, got %v", got)
		}
		if got := plugin.DetectConflict(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); got != nil {
			t.Fatalf("expected nil for non-service kind, got %v", got)
		}
	})
}
