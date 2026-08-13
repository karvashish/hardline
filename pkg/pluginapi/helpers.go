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
			if b.File.Existed != a.File.Existed ||
				b.File.ContentB64 != a.File.ContentB64 ||
				b.File.Mode != a.File.Mode ||
				b.File.Owner != a.File.Owner ||
				b.File.Group != a.File.Group {
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
			if b.Service.Active != a.Service.Active ||
				b.Service.Enabled != a.Service.Enabled ||
				b.Service.EnabledState != a.Service.EnabledState ||
				b.Service.ActiveState != a.Service.ActiveState {
				return true
			}
		case ObjectPackage:
			if b.Package == nil || a.Package == nil {
				return b.Package != a.Package
			}
			if b.Package.WasInstalled != a.Package.WasInstalled ||
				b.Package.Version != a.Package.Version ||
				b.Package.PinSpec != a.Package.PinSpec {
				return true
			}
		case ObjectConfigLine:
			if b.ConfigLine == nil || a.ConfigLine == nil {
				return b.ConfigLine != a.ConfigLine
			}
			if b.ConfigLine.Path != a.ConfigLine.Path ||
				b.ConfigLine.Line != a.ConfigLine.Line ||
				b.ConfigLine.FileExisted != a.ConfigLine.FileExisted ||
				b.ConfigLine.Added != a.ConfigLine.Added {
				return true
			}
		}
	}
	return false
}

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

const MaxSnapshotBytes = 1 << 20

func ParseFileMode(raw string) (os.FileMode, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, fmt.Errorf("no file mode recorded")
	}
	parsed, err := strconv.ParseUint(trimmed, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid file mode %q (expected octal, e.g. 640): %w", raw, err)
	}
	if parsed > 0o7777 {
		return 0, fmt.Errorf("invalid file mode %q: out of range", raw)
	}
	return os.FileMode(parsed), nil
}

func SnapshotRemoteFile(host Host, remotePath string) (FileSnapshot, error) {
	if host == nil {
		return FileSnapshot{}, fmt.Errorf("host is required")
	}

	snap := FileSnapshot{Path: remotePath}

	statOut, err := host.RunRootWithOutput("stat -L -c '%F|%a|%U|%G|%s' " + ShellArg(remotePath) + " 2>/dev/null || true")
	if err != nil {
		return snap, fmt.Errorf("stat %q: %w", remotePath, err)
	}
	statLine := strings.TrimSpace(statOut)
	if statLine == "" {
		snap.Existed = false
		return snap, nil
	}

	fields := strings.Split(statLine, "|")
	if len(fields) != 5 {
		return snap, fmt.Errorf("parse stat output for %q: unexpected format %q", remotePath, statLine)
	}
	if fields[0] != "regular file" && fields[0] != "regular empty file" {
		return snap, fmt.Errorf("refusing to snapshot %q: it is a %s, not a regular file", remotePath, fields[0])
	}
	size, err := strconv.ParseInt(fields[4], 10, 64)
	if err != nil {
		return snap, fmt.Errorf("parse stat size for %q: %w", remotePath, err)
	}
	if size > MaxSnapshotBytes {
		return snap, fmt.Errorf("refusing to snapshot %q: %d bytes exceeds the %d byte limit", remotePath, size, MaxSnapshotBytes)
	}

	if err := host.RunRoot("test ! -L " + ShellArg(remotePath)); err != nil {
		return snap, fmt.Errorf("refusing to snapshot %q: it is a symlink", remotePath)
	}

	snap.Existed = true
	snap.Mode = fields[1]
	snap.Owner = fields[2]
	snap.Group = fields[3]

	content, err := host.ReadRootFile(remotePath)
	if err != nil {
		return snap, err
	}
	if len(content) > MaxSnapshotBytes {
		return snap, fmt.Errorf("refusing to snapshot %q: %d bytes exceeds the %d byte limit", remotePath, len(content), MaxSnapshotBytes)
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

func RestoreFileSnapshot(host Host, snap FileSnapshot) error {
	if err := EnforceManagedPath(snap.Path); err != nil {
		return err
	}

	if !snap.Existed {
		return host.RunRoot("rm -f " + ShellArg(snap.Path))
	}

	mode, err := ParseFileMode(snap.Mode)
	if err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
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

	if snap.Owner == "" || snap.Group == "" {
		return fmt.Errorf("restore file %q: the journal records no owner or group", snap.Path)
	}
	if err := host.RunRoot("chown " + ShellArg(snap.Owner+":"+snap.Group) + " " + ShellArg(snap.Path)); err != nil {
		return fmt.Errorf("restore ownership of %q: %w", snap.Path, err)
	}
	return nil
}

func FileSnapshotConflict(host Host, snap FileSnapshot) []string {
	current, err := SnapshotRemoteFile(host, snap.Path)
	if err != nil {
		return []string{fmt.Sprintf("%s: cannot be inspected (%v)", snap.Path, err)}
	}

	if !snap.Existed {
		if current.Existed {
			return []string{fmt.Sprintf("%s: journal recorded no file here but one exists now (created since apply); rolling back deletes it", snap.Path)}
		}
		return nil
	}

	if !current.Existed {
		return []string{fmt.Sprintf("%s: journal expects this file to exist but it is now absent (removed since apply)", snap.Path)}
	}

	var conflicts []string
	if current.ContentB64 != snap.ContentB64 {
		conflicts = append(conflicts, fmt.Sprintf("%s: current content differs from what this profile wrote (modified since apply)", snap.Path))
	}
	if current.Mode != snap.Mode {
		conflicts = append(conflicts, fmt.Sprintf("%s: mode is %s but this profile left it %s (changed since apply)", snap.Path, current.Mode, snap.Mode))
	}
	if current.Owner != snap.Owner || current.Group != snap.Group {
		conflicts = append(conflicts, fmt.Sprintf("%s: owner is %s:%s but this profile left it %s:%s (changed since apply)",
			snap.Path, current.Owner, current.Group, snap.Owner, snap.Group))
	}
	return conflicts
}
