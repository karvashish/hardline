package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"plugin"
	"sort"
	"strings"

	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	pluginDirName  = "plugins"
	pluginSymbolV1 = "HardlinePluginV1"
)

type pluginLookup interface {
	Lookup(string) (plugin.Symbol, error)
}

var (
	executablePath   = os.Executable
	readDirEntries   = os.ReadDir
	openSharedObject = func(path string) (pluginLookup, error) {
		return plugin.Open(path)
	}
	registerPluginAction = func(loaded pluginapi.Plugin) error {
		return registry.Shared().Register(loaded)
	}
)

func LoadFromBinaryDir() error {
	exe, err := executablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	pluginDir := filepath.Join(filepath.Dir(exe), pluginDirName)
	return LoadFromDir(pluginDir)
}

func LoadFromDir(dir string) error {
	entries, err := readDirEntries(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Debugf("plugins: directory %q not found, skipping\n", dir)
			return nil
		}
		return fmt.Errorf("read plugins directory %q: %w", dir, err)
	}

	var pluginFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if strings.EqualFold(filepath.Ext(name), ".so") {
			pluginFiles = append(pluginFiles, name)
		}
	}
	sort.Strings(pluginFiles)

	for _, name := range pluginFiles {
		path := filepath.Join(dir, name)
		if err := loadPluginFile(path); err != nil {
			return err
		}
	}

	return nil
}

func loadPluginFile(path string) error {
	pl, err := openSharedObject(path)
	if err != nil {
		return fmt.Errorf("open plugin %q: %w", path, err)
	}
	sym, err := pl.Lookup(pluginSymbolV1)
	if err != nil {
		return fmt.Errorf("plugin %q missing symbol %q: %w", path, pluginSymbolV1, err)
	}

	loaded, err := resolvePlugin(sym, path)
	if err != nil {
		return err
	}
	if err := registerPlugin(loaded, path); err != nil {
		return err
	}
	logger.Debugf("plugins: loaded %q\n", path)
	return nil
}

func resolvePlugin(sym plugin.Symbol, path string) (pluginapi.Plugin, error) {
	switch v := sym.(type) {
	case *pluginapi.Plugin:
		if v == nil {
			return pluginapi.Plugin{}, fmt.Errorf("plugin %q symbol %q is nil", path, pluginSymbolV1)
		}
		return *v, nil
	default:
		return pluginapi.Plugin{}, fmt.Errorf(
			"plugin %q symbol %q has unsupported type %T (expected *pluginapi.Plugin)",
			path, pluginSymbolV1, sym,
		)
	}
}

func registerPlugin(loaded pluginapi.Plugin, path string) error {
	name := strings.TrimSpace(loaded.Name)
	if name == "" {
		name = filepath.Base(path)
	}
	if err := registerPluginAction(loaded); err != nil {
		return fmt.Errorf("register plugin %q (%s): %w", path, name, err)
	}
	return nil
}
