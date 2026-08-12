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
	lstatPath        = os.Lstat
	currentUID       = os.Geteuid
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
// code with root privileges (via passwordless sudo), so the directory and every
// artifact in it are checked before anything is opened: each must be a real
// directory or regular file rather than a symlink, must not be writable by
// group or others, and must be owned by root or by the user running hardline.
// Anything else is refused rather than warned about.
//
// What this cannot check is where the plugin came from. Source them from the
// same package or release artifact as the binary itself.
func LoadFromBinaryDir() error {
	exe, err := executablePath()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	pluginDir := filepath.Join(filepath.Dir(exe), pluginDirName)
	return LoadFromDir(pluginDir)
}

// assertTrustedArtifact holds one path to the rules the trust model already
// stated but nothing enforced. Everything under this directory runs as root, so
// the question is not whether the file looks like a plugin but whether anyone
// other than root or the invoking user could have put it there: a group-writable
// directory, a symlink pointing somewhere else, or a file owned by a third party
// are each enough to hand root away.
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
	// Checked per artifact, not once for the directory: a directory nobody else
	// can write to can still hold a file someone else owns, left there before
	// the directory was tightened.
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
