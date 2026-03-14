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
	"github.com/karvashish/hardline/pkg/profile"
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
				pluginSymbolV1: &pluginapi.Plugin{Name: filepath.Base(path)},
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

func TestResolvePlugin(t *testing.T) {
	base := pluginapi.Plugin{Name: "x"}

	cases := []struct {
		name    string
		symbol  any
		wantErr string
	}{
		{name: "pointer", symbol: &base},
		{name: "nil pointer", symbol: (*pluginapi.Plugin)(nil), wantErr: "is nil"},
		{name: "value unsupported", symbol: base, wantErr: "unsupported type"},
		{name: "func unsupported", symbol: func() pluginapi.Plugin { return base }, wantErr: "unsupported type"},
		{name: "unsupported", symbol: 123, wantErr: "unsupported type"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePlugin(tc.symbol, "/tmp/x.so")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolvePlugin failed: %v", err)
			}
			if got.Name != base.Name {
				t.Fatalf("unexpected plugin: %+v", got)
			}
		})
	}
}

func TestRegisterPlugin(t *testing.T) {
	t.Run("plugin registration error", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		registerPluginAction = func(pluginapi.Plugin) error { return errors.New("register fail") }
		err := registerPlugin(validLoaderPlugin("x"), "/tmp/p.so")
		if err == nil || !strings.Contains(err.Error(), "register fail") {
			t.Fatalf("expected plugin registration error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		restore := stubLoaderDeps()
		defer restore()

		var got pluginapi.Plugin
		registerPluginAction = func(plugin pluginapi.Plugin) error {
			got = plugin
			return nil
		}

		err := registerPlugin(validLoaderPlugin("ok"), "/tmp/ok.so")
		if err != nil {
			t.Fatalf("registerPlugin failed: %v", err)
		}
		if got.Name != "ok" {
			t.Fatalf("unexpected plugin passed to registrar: %+v", got)
		}
	})
}

func stubLoaderDeps() func() {
	prevExec := executablePath
	prevReadDir := readDirEntries
	prevOpen := openSharedObject
	prevRegister := registerPluginAction

	executablePath = os.Executable
	readDirEntries = os.ReadDir
	registerPluginAction = func(pluginapi.Plugin) error { return nil }
	openSharedObject = func(path string) (pluginLookup, error) {
		return fakePlugin{symbols: map[string]any{
			pluginSymbolV1: &pluginapi.Plugin{Name: filepath.Base(path)},
		}}, nil
	}

	return func() {
		executablePath = prevExec
		readDirEntries = prevReadDir
		openSharedObject = prevOpen
		registerPluginAction = prevRegister
	}
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

func validLoaderPlugin(name string) pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               name,
		InternalValidation: true,
		Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
		Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{}, nil
		},
		Rollback: func(pluginapi.RollbackContext, profile.Step) (pluginapi.StepRecord, error) {
			return pluginapi.StepRecord{}, nil
		},
	}
}
