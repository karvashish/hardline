package plugins

import (
	"errors"
	"fmt"
	"io/fs"
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
	statPath         = os.Stat
	openSharedObject = func(path string) (pluginLookup, error) {
		return plugin.Open(path)
	}
	registerPluginAction = func(loaded pluginapi.Plugin) error {
		return registry.Shared().Register(loaded)
	}
)

// LoadFromBinaryDir loads external plugins from the "plugins/" directory
// adjacent to the hardline binary.
//
// Trust model: external plugins are Go shared objects (.so) and are NOT
// signature-verified. Any file placed in this directory executes arbitrary
// code with root privileges (via passwordless sudo). Operators must ensure:
//   - The binary directory and plugins/ subdirectory are owned by root and
//     not world-writable (chmod 755 or stricter).
//   - Plugins are sourced from a trusted, controlled location (e.g. the same
//     package or release artifact as the binary itself).
//
// This directory is NOT multi-tenant safe. Do not allow untrusted users to
// write to it.
func LoadFromBinaryDir() error {
	exe, err := executablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	pluginDir := filepath.Join(filepath.Dir(exe), pluginDirName)
	return LoadFromDir(pluginDir)
}

// checkDirPermissions verifies the plugin directory is not world-writable.
// External plugins execute arbitrary code with root privileges, so a
// world-writable directory is a privilege-escalation vector.
func checkDirPermissions(dir string) error {
	info, err := statPath(dir)
	if err != nil {
		return fmt.Errorf("stat plugins directory %q: %w", dir, err)
	}
	mode := info.Mode().Perm()
	if mode&fs.FileMode(0o002) != 0 {
		return fmt.Errorf("plugins directory %q is world-writable (mode %04o); refusing to load plugins — fix with: chmod o-w %q", dir, mode, dir)
	}
	return nil
}

// LoadFromDir loads all .so plugin files from dir into the shared registry.
// See LoadFromBinaryDir for the trust model that applies to this directory.
func LoadFromDir(dir string) error {
	entries, err := readDirEntries(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Debugf("plugins: directory %q not found, skipping\n", dir)
			return nil
		}
		return fmt.Errorf("read plugins directory %q: %w", dir, err)
	}

	if err := checkDirPermissions(dir); err != nil {
		return err
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

	if len(pluginFiles) > 0 {
		logger.Warnf("plugins: loading %d external plugin(s) from %q — these run as root and are not signature-verified; ensure this directory is not world-writable\n", len(pluginFiles), dir)
	}

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
