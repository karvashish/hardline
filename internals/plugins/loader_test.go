package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"reflect"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

type fakePlugin struct {
	symbols   map[string]any
	lookupErr error
}

func (f fakePlugin) Lookup(name string) (plugin.Symbol, error) {
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	sym, ok := f.symbols[name]
	if !ok {
		return nil, fmt.Errorf("symbol %q not found", name)
	}
	return sym, nil
}

func TestLoadFromBinaryDir(t *testing.T) {
	t.Run("executable error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		executablePath = func() (string, error) { return "", errors.New("boom") }
		err := LoadFromBinaryDir()
		if err == nil || !strings.Contains(err.Error(), "resolve executable path") {
			t.Fatalf("expected executable path error, got %v", err)
		}
	})

	t.Run("uses sibling plugins directory", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		executablePath = func() (string, error) { return "/opt/hardline/hardline", nil }
		var gotDir string
		readDirEntries = func(dir string) ([]os.DirEntry, error) {
			gotDir = dir
			return nil, os.ErrNotExist
		}

		if err := LoadFromBinaryDir(); err != nil {
			t.Fatalf("LoadFromBinaryDir failed: %v", err)
		}
		if gotDir != "/opt/hardline/plugins" {
			t.Fatalf("unexpected plugins dir: %q", gotDir)
		}
	})
}

func TestLoadFromDir(t *testing.T) {
	t.Run("missing directory is no-op", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		err := LoadFromDir(filepath.Join(t.TempDir(), "missing-plugins"))
		if err != nil {
			t.Fatalf("expected missing plugins directory to be ignored, got %v", err)
		}
	})

	t.Run("read dir error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		readDirEntries = func(string) ([]os.DirEntry, error) {
			return nil, errors.New("bad read")
		}
		err := LoadFromDir("/tmp/plugins")
		if err == nil || !strings.Contains(err.Error(), "read plugins directory") {
			t.Fatalf("expected read dir error, got %v", err)
		}
	})

	t.Run("loads sorted .so files and skips others", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "b.so"))
		mustWrite(t, filepath.Join(dir, "a.so"))
		mustWrite(t, filepath.Join(dir, "note.txt"))
		if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
			t.Fatalf("mkdir nested: %v", err)
		}
		mustWrite(t, filepath.Join(dir, "nested", "x.so"))

		var opened []string
		openSharedObject = func(path string) (pluginLookup, error) {
			opened = append(opened, filepath.Base(path))
			return fakePlugin{symbols: map[string]any{
				pluginSymbolV1: pluginapi.PluginBundle{Name: filepath.Base(path)},
			}}, nil
		}

		if err := LoadFromDir(dir); err != nil {
			t.Fatalf("LoadFromDir failed: %v", err)
		}

		want := []string{"a.so", "b.so"}
		if !reflect.DeepEqual(opened, want) {
			t.Fatalf("unexpected plugin load order: got=%v want=%v", opened, want)
		}
	})

	t.Run("open error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "broken.so"))
		openSharedObject = func(path string) (pluginLookup, error) {
			return nil, errors.New("bad plugin")
		}

		err := LoadFromDir(dir)
		if err == nil || !strings.Contains(err.Error(), "open plugin") {
			t.Fatalf("expected open plugin error, got %v", err)
		}
	})

	t.Run("missing symbol error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		dir := t.TempDir()
		mustWrite(t, filepath.Join(dir, "missing.so"))
		openSharedObject = func(path string) (pluginLookup, error) {
			return fakePlugin{symbols: map[string]any{}}, nil
		}

		err := LoadFromDir(dir)
		if err == nil || !strings.Contains(err.Error(), "missing symbol") {
			t.Fatalf("expected missing symbol error, got %v", err)
		}
	})
}

func TestResolvePluginBundle(t *testing.T) {
	base := pluginapi.PluginBundle{Name: "x"}

	cases := []struct {
		name    string
		symbol  any
		wantErr string
	}{
		{name: "value", symbol: base},
		{name: "pointer", symbol: &base},
		{name: "func value", symbol: func() pluginapi.PluginBundle { return base }},
		{name: "func pointer", symbol: ptrFuncBundle(func() pluginapi.PluginBundle { return base })},
		{name: "func value with error", symbol: func() (pluginapi.PluginBundle, error) { return base, nil }},
		{name: "func pointer with error", symbol: ptrFuncBundleErr(func() (pluginapi.PluginBundle, error) { return base, nil })},
		{name: "nil pointer", symbol: (*pluginapi.PluginBundle)(nil), wantErr: "is nil"},
		{name: "func returns error", symbol: func() (pluginapi.PluginBundle, error) { return pluginapi.PluginBundle{}, errors.New("boom") }, wantErr: "boom"},
		{name: "unsupported", symbol: 123, wantErr: "unsupported type"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePluginBundle(tc.symbol, "/tmp/x.so")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePluginBundle failed: %v", err)
			}
			if got.Name != base.Name {
				t.Fatalf("unexpected bundle: %+v", got)
			}
		})
	}
}

func TestRegisterPluginBundle(t *testing.T) {
	t.Run("apply registration error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		registerApplyAction = func(pluginapi.ApplyHandler) error { return errors.New("apply fail") }
		err := registerPluginBundle(pluginapi.PluginBundle{
			Name:          "p",
			ApplyHandlers: []pluginapi.ApplyHandler{{Type: "x"}},
		}, "/tmp/p.so")
		if err == nil || !strings.Contains(err.Error(), "apply action") {
			t.Fatalf("expected apply registration error, got %v", err)
		}
	})

	t.Run("plan registration error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		registerPlanAction = func(pluginapi.PlanHandler) error { return errors.New("plan fail") }
		err := registerPluginBundle(pluginapi.PluginBundle{
			Name:         "p",
			PlanHandlers: []pluginapi.PlanHandler{{Type: "y"}},
		}, "/tmp/p.so")
		if err == nil || !strings.Contains(err.Error(), "plan action") {
			t.Fatalf("expected plan registration error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		var applyCount, planCount, rollbackCount int
		registerApplyAction = func(pluginapi.ApplyHandler) error {
			applyCount++
			return nil
		}
		registerPlanAction = func(pluginapi.PlanHandler) error {
			planCount++
			return nil
		}
		registerRollbackAction = func(pluginapi.RollbackHandler) error {
			rollbackCount++
			return nil
		}

		err := registerPluginBundle(pluginapi.PluginBundle{
			Name:             "ok",
			ApplyHandlers:    []pluginapi.ApplyHandler{{Type: "a1"}, {Type: "a2"}},
			PlanHandlers:     []pluginapi.PlanHandler{{Type: "p1"}},
			RollbackHandlers: []pluginapi.RollbackHandler{{Type: "r1"}},
		}, "/tmp/ok.so")
		if err != nil {
			t.Fatalf("registerPluginBundle failed: %v", err)
		}
		if applyCount != 2 || planCount != 1 || rollbackCount != 1 {
			t.Fatalf("unexpected registration counts: apply=%d plan=%d rollback=%d", applyCount, planCount, rollbackCount)
		}
	})

	t.Run("rollback registration error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		registerRollbackAction = func(pluginapi.RollbackHandler) error { return errors.New("rollback fail") }
		err := registerPluginBundle(pluginapi.PluginBundle{
			Name:             "p",
			RollbackHandlers: []pluginapi.RollbackHandler{{Type: "z"}},
		}, "/tmp/p.so")
		if err == nil || !strings.Contains(err.Error(), "rollback action") {
			t.Fatalf("expected rollback registration error, got %v", err)
		}
	})
}

func stubLoaderDeps() func() {
	prevExec := executablePath
	prevReadDir := readDirEntries
	prevOpen := openSharedObject
	prevRegApply := registerApplyAction
	prevRegPlan := registerPlanAction
	prevRegRollback := registerRollbackAction

	executablePath = os.Executable
	readDirEntries = os.ReadDir
	registerApplyAction = func(pluginapi.ApplyHandler) error { return nil }
	registerPlanAction = func(pluginapi.PlanHandler) error { return nil }
	registerRollbackAction = func(pluginapi.RollbackHandler) error { return nil }
	openSharedObject = func(path string) (pluginLookup, error) {
		return fakePlugin{symbols: map[string]any{
			pluginSymbolV1: pluginapi.PluginBundle{Name: filepath.Base(path)},
		}}, nil
	}

	return func() {
		executablePath = prevExec
		readDirEntries = prevReadDir
		openSharedObject = prevOpen
		registerApplyAction = prevRegApply
		registerPlanAction = prevRegPlan
		registerRollbackAction = prevRegRollback
	}
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func ptrFuncBundle(fn func() pluginapi.PluginBundle) *func() pluginapi.PluginBundle {
	return &fn
}

func ptrFuncBundleErr(fn func() (pluginapi.PluginBundle, error)) *func() (pluginapi.PluginBundle, error) {
	return &fn
}
