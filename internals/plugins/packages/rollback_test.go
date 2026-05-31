package packages

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestRestorePackageBestEffort(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		err := restorePackageBestEffort(packagesRuntimeStub{}, pluginapi.PackageState{Name: " "})
		if err == nil || !strings.Contains(err.Error(), "package name is empty") {
			t.Fatalf("expected empty name error, got %v", err)
		}
	})

	t.Run("install rolled back via purge", func(t *testing.T) {
		var cmds []string
		host := packagesRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		err := restorePackageBestEffort(host, pluginapi.PackageState{Name: "fail2ban", RequestedInstall: true, WasInstalled: false})
		if err != nil {
			t.Fatalf("restorePackageBestEffort failed: %v", err)
		}
		if len(cmds) != 1 || !strings.Contains(cmds[0], "apt-get purge") {
			t.Fatalf("expected purge command, got %#v", cmds)
		}
	})

	t.Run("purge rolled back via versioned install", func(t *testing.T) {
		var cmds []string
		host := packagesRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		err := restorePackageBestEffort(host, pluginapi.PackageState{Name: "telnet", RequestedPurge: true, WasInstalled: true, Version: "1.2.3"})
		if err != nil {
			t.Fatalf("restorePackageBestEffort failed: %v", err)
		}
		if len(cmds) != 1 || !strings.Contains(cmds[0], "telnet=1.2.3") {
			t.Fatalf("expected versioned install, got %#v", cmds)
		}
	})

	t.Run("versioned install falls back to plain", func(t *testing.T) {
		var count int
		host := packagesRuntimeStub{runRoot: func(cmd string) error {
			count++
			if strings.Contains(cmd, "pkg=1.0") {
				return errors.New("version unavailable")
			}
			return nil
		}}
		err := restorePackageBestEffort(host, pluginapi.PackageState{Name: "pkg", RequestedPurge: true, WasInstalled: true, Version: "1.0"})
		if err != nil {
			t.Fatalf("restorePackageBestEffort failed: %v", err)
		}
		if count != 2 {
			t.Fatalf("expected versioned + fallback install, count=%d", count)
		}
	})

	t.Run("purge error", func(t *testing.T) {
		host := packagesRuntimeStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "apt-get purge") {
				return errors.New("purge boom")
			}
			return nil
		}}
		err := restorePackageBestEffort(host, pluginapi.PackageState{Name: "pkg", RequestedInstall: true, WasInstalled: false})
		if err == nil || !strings.Contains(err.Error(), "purge package") {
			t.Fatalf("expected purge error, got %v", err)
		}
	})

	t.Run("reinstall error", func(t *testing.T) {
		host := packagesRuntimeStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "apt-get install -y") {
				return errors.New("install boom")
			}
			return nil
		}}
		err := restorePackageBestEffort(host, pluginapi.PackageState{Name: "pkg", RequestedPurge: true, WasInstalled: true, Version: "1.0"})
		if err == nil || !strings.Contains(err.Error(), "reinstall package") {
			t.Fatalf("expected reinstall error, got %v", err)
		}
	})
}

func TestPackageStateConflict(t *testing.T) {
	t.Run("empty name", func(t *testing.T) {
		if got := packageStateConflict(packagesRuntimeStub{}, pluginapi.PackageState{Name: " "}); got != nil {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("installed matches", func(t *testing.T) {
		host := packagesRuntimeStub{installed: map[string]bool{"curl": true}}
		if got := packageStateConflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true}); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("installed differs", func(t *testing.T) {
		host := packagesRuntimeStub{installed: map[string]bool{}}
		got := packageStateConflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true})
		if len(got) != 1 || !strings.Contains(got[0], "changed since apply") {
			t.Fatalf("expected install conflict, got %v", got)
		}
	})

	t.Run("version mismatch", func(t *testing.T) {
		host := packagesRuntimeStub{
			installed:         map[string]bool{"curl": true},
			runRootWithOutput: func(string) (string, error) { return "2.0.0", nil },
		}
		got := packageStateConflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: "1.0.0"})
		if len(got) != 1 || !strings.Contains(got[0], "upgraded since apply") {
			t.Fatalf("expected version conflict, got %v", got)
		}
	})

	t.Run("version matches", func(t *testing.T) {
		host := packagesRuntimeStub{
			installed:         map[string]bool{"curl": true},
			runRootWithOutput: func(string) (string, error) { return "1.0.0", nil },
		}
		if got := packageStateConflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: "1.0.0"}); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})

	t.Run("empty journal version skips", func(t *testing.T) {
		host := packagesRuntimeStub{
			installed:         map[string]bool{"curl": true},
			runRootWithOutput: func(string) (string, error) { return "2.0.0", nil },
		}
		if got := packageStateConflict(host, pluginapi.PackageState{Name: "curl", WasInstalled: true, Version: ""}); len(got) != 0 {
			t.Fatalf("expected no conflicts, got %v", got)
		}
	})
}

func TestQueryPackageVersion(t *testing.T) {
	host := packagesRuntimeStub{runRootWithOutput: func(string) (string, error) { return "  1.0.0\n", nil }}
	if v := queryPackageVersion(host, "curl"); v != "1.0.0" {
		t.Fatalf("expected trimmed version, got %q", v)
	}

	errHost := packagesRuntimeStub{runRootWithOutput: func(string) (string, error) { return "", errors.New("boom") }}
	if v := queryPackageVersion(errHost, "curl"); v != "" {
		t.Fatalf("expected empty version on error, got %q", v)
	}
}

func TestPackagesPluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(packagesRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage})
		if err == nil || !strings.Contains(err.Error(), "missing package snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := plugin.Rollback(packagesRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := plugin.Rollback(packagesRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile})
		if err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})

	t.Run("package rolled back", func(t *testing.T) {
		var cmds []string
		host := packagesRuntimeStub{runRoot: func(cmd string) error { cmds = append(cmds, cmd); return nil }}
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "fail2ban", RequestedInstall: true, WasInstalled: false}}
		if err := plugin.Rollback(host, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
		if len(cmds) != 1 {
			t.Fatalf("expected one command, got %#v", cmds)
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		host := packagesRuntimeStub{installed: map[string]bool{}}
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage, Package: &pluginapi.PackageState{Name: "curl", WasInstalled: true}}
		if got := plugin.DetectConflict(host, obj); len(got) != 1 {
			t.Fatalf("expected one conflict, got %v", got)
		}
		if got := plugin.DetectConflict(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); got != nil {
			t.Fatalf("expected nil for non-package kind, got %v", got)
		}
	})
}
