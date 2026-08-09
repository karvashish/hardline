package pluginapi

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// ShellArg wraps s as a single POSIX sh word. Unlike strconv.Quote, which
// emits Go double-quoted syntax, single quotes suppress command substitution
// and parameter expansion, so profile-supplied values cannot execute as root.
func ShellArg(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func CapturesDiffer(before, after CaptureResult) bool {
	if len(before.Objects) != len(after.Objects) {
		return true
	}
	for i := range before.Objects {
		b, a := before.Objects[i], after.Objects[i]
		if b.Kind != a.Kind {
			return true
		}
		switch b.Kind {
		case ObjectFile:
			if b.File == nil || a.File == nil {
				return b.File != a.File
			}
			if b.File.Existed != a.File.Existed || b.File.ContentB64 != a.File.ContentB64 {
				return true
			}
		case ObjectFileMeta:
			if b.FileMeta == nil || a.FileMeta == nil {
				return b.FileMeta != a.FileMeta
			}
			if b.FileMeta.Existed != a.FileMeta.Existed ||
				b.FileMeta.Mode != a.FileMeta.Mode ||
				b.FileMeta.Owner != a.FileMeta.Owner ||
				b.FileMeta.Group != a.FileMeta.Group ||
				b.FileMeta.Attrs != a.FileMeta.Attrs {
				return true
			}
		case ObjectService:
			if b.Service == nil || a.Service == nil {
				return b.Service != a.Service
			}
			if b.Service.Active != a.Service.Active || b.Service.Enabled != a.Service.Enabled {
				return true
			}
		case ObjectPackage:
			if b.Package == nil || a.Package == nil {
				return b.Package != a.Package
			}
			if b.Package.WasInstalled != a.Package.WasInstalled {
				return true
			}
		}
	}
	return false
}

// managedPathPattern is the whitelist for every root-executed destination path.
// It excludes $, backtick, parentheses, quotes, backslash, glob characters and
// whitespace, so an accepted path cannot alter a command even before quoting.
var managedPathPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

func EnforceManagedPath(dest string) error {
	p := strings.TrimSpace(dest)
	if p == "" {
		return fmt.Errorf("managed destination path is empty")
	}
	if !managedPathPattern.MatchString(p) {
		return fmt.Errorf("destination %q contains characters outside the allowed set [A-Za-z0-9._/-]", p)
	}
	if !strings.HasPrefix(p, "/etc/") {
		return fmt.Errorf("destination %q is outside /etc managed scope", p)
	}
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("destination %q is not a normalized absolute path", p)
	}

	// Drop-in directories resolve a conflict in one of two opposite ways, and a
	// managed file has to sort on the winning side of whichever one it is in.
	// sysctl.d, journald.conf.d and the rest take the last value, so 99-hardline
	// sorts last and wins. sshd reads its includes lexically and, unless a
	// keyword says otherwise, keeps the first value obtained, so there a
	// 99-hardline file loses to any earlier vendor or cloud-init drop-in and
	// 00-hardline is what wins. Both prefixes are hardline's own; nothing else
	// is accepted, so a managed file stays recognizable either way.
	base := path.Base(p)
	if !strings.HasPrefix(base, "99-hardline") && !strings.HasPrefix(base, "00-hardline") {
		return fmt.Errorf("destination %q must use a hardline prefix: 00-hardline* where the first match wins (sshd_config.d), 99-hardline* otherwise", p)
	}

	ext := strings.ToLower(path.Ext(base))
	switch ext {
	case ".conf", ".nft", ".rules":
		return nil
	default:
		return fmt.Errorf("destination %q has unsupported extension %q", p, ext)
	}
}

func SnapshotRemoteFile(host Host, remotePath string) (FileSnapshot, error) {
	if host == nil {
		return FileSnapshot{}, fmt.Errorf("host is required")
	}

	snap := FileSnapshot{Path: remotePath}

	testCmd := "test -e " + ShellArg(remotePath)
	if err := host.RunRoot(testCmd); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	modeCmd := "stat -c %a " + ShellArg(remotePath)
	modeOut, err := host.RunRootWithOutput(modeCmd)
	if err != nil {
		return snap, err
	}
	snap.Mode = strings.TrimSpace(modeOut)

	content, err := host.ReadRootFile(remotePath)
	if err != nil {
		return snap, err
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

// RestoreFileSnapshot reverts a managed file to the state captured in snap:
// deleting it when it did not previously exist, otherwise rewriting its content
// and mode. Shared by the template and firewall plugins, which both emit
// ObjectFile.
func RestoreFileSnapshot(host Host, snap FileSnapshot) error {
	if err := EnforceManagedPath(snap.Path); err != nil {
		return err
	}

	if !snap.Existed {
		return host.RunRoot("rm -f " + ShellArg(snap.Path))
	}

	mode := os.FileMode(0o600)
	if strings.TrimSpace(snap.Mode) != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(snap.Mode), 8, 32); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	content, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("decode snapshot content for %q: %w", snap.Path, err)
	}

	dir := path.Dir(snap.Path)
	if dir != "" && dir != "." {
		if err := host.RunRoot("mkdir -p " + ShellArg(dir)); err != nil {
			return fmt.Errorf("ensure directory %q: %w", dir, err)
		}
	}

	if err := host.WriteRootFile(snap.Path, content, mode); err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
	}
	return nil
}

// FileSnapshotConflict reports whether the remote file drifted from the
// post-apply content recorded in snap. An empty result means no conflict.
func FileSnapshotConflict(host Host, snap FileSnapshot) []string {
	if !snap.Existed {
		return nil
	}
	expectedContent, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return nil
	}
	current, err := host.ReadRootFile(snap.Path)
	if err != nil {
		return []string{fmt.Sprintf("%s: journal expects file to exist but it cannot be read (%v)", snap.Path, err)}
	}
	if current != string(expectedContent) {
		return []string{fmt.Sprintf("%s: current content differs from what this profile wrote (modified since apply)", snap.Path)}
	}
	return nil
}
