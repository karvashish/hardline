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
	lstatPath        = os.Lstat
	currentUID       = os.Geteuid
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

func assertTrustedArtifact(path string, wantDir bool) error {
	info, err := lstatPath(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}

	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%q is a symlink; refusing to load plugins through one, because what it points at is not what was checked", path)
	case wantDir && !info.IsDir():
		return fmt.Errorf("plugins path %q is not a directory", path)
	case !wantDir && !info.Mode().IsRegular():
		return fmt.Errorf("plugin %q is not a regular file", path)
	}

	if mode := info.Mode().Perm(); mode&0o022 != 0 {
		fix := "chmod go-w " + path
		return fmt.Errorf("%q is writable by group or others (mode %04o); refusing to load plugins — fix with: %s", path, mode, fix)
	}

	uid, ok := fileOwnerUID(info)
	if !ok {
		return nil
	}
	if uid != 0 && int(uid) != currentUID() {
		return fmt.Errorf("%q is owned by uid %d, which is neither root nor the user running hardline (uid %d); refusing to load plugins", path, uid, currentUID())
	}
	return nil
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

	if err := assertTrustedArtifact(dir, true); err != nil {
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
	if err := assertTrustedArtifact(path, false); err != nil {
		return err
	}

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
