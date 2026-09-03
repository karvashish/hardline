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
	beforeByKey := make(map[string]ObjectRecord, len(before.Objects))
	for _, obj := range before.Objects {
		beforeByKey[ObjectKey(obj)] = obj
	}
	if len(beforeByKey) != len(before.Objects) {
		return true
	}

	for _, a := range after.Objects {
		b, paired := beforeByKey[ObjectKey(a)]
		if !paired {
			return true
		}
		// A missing payload is this object's answer, not the whole capture's: returning here
		// would let one object decide for every object behind it.
		bHas, aHas := objectPayloadPresent(b), objectPayloadPresent(a)
		if bHas != aHas {
			return true
		}
		if !bHas {
			continue
		}
		switch b.Kind {
		case ObjectFile:
			if b.File.Existed != a.File.Existed ||
				b.File.ContentB64 != a.File.ContentB64 ||
				b.File.Mode != a.File.Mode ||
				b.File.Owner != a.File.Owner ||
				b.File.Group != a.File.Group {
				return true
			}
		case ObjectFileMeta:
			if b.FileMeta.Existed != a.FileMeta.Existed ||
				b.FileMeta.Mode != a.FileMeta.Mode ||
				b.FileMeta.Owner != a.FileMeta.Owner ||
				b.FileMeta.Group != a.FileMeta.Group ||
				b.FileMeta.Attrs != a.FileMeta.Attrs {
				return true
			}
		case ObjectService:
			if b.Service.Active != a.Service.Active ||
				b.Service.Enabled != a.Service.Enabled ||
				b.Service.EnabledState != a.Service.EnabledState ||
				b.Service.ActiveState != a.Service.ActiveState {
				return true
			}
		case ObjectPackage:
			if b.Package.WasInstalled != a.Package.WasInstalled ||
				b.Package.Version != a.Package.Version ||
				b.Package.PinSpec != a.Package.PinSpec {
				return true
			}
		case ObjectRuntimePolicy:
			if b.RuntimePolicy.Name != a.RuntimePolicy.Name ||
				b.RuntimePolicy.State != a.RuntimePolicy.State {
				return true
			}
		}
	}
	return false
}

// Two captures of one step describe the same objects, but nothing in the plugin contract fixes the
// order a plugin emits them in. Pairing them by what they identify rather than by position is what
// lets a caller compare or resume them without depending on that.
func ObjectKey(o ObjectRecord) string {
	switch o.Kind {
	case ObjectFile:
		if o.File != nil {
			return string(o.Kind) + "\x00" + o.File.Path
		}
	case ObjectFileMeta:
		if o.FileMeta != nil {
			return string(o.Kind) + "\x00" + o.FileMeta.Path
		}
	case ObjectService:
		if o.Service != nil {
			return string(o.Kind) + "\x00" + o.Service.Unit
		}
	case ObjectPackage:
		if o.Package != nil {
			return string(o.Kind) + "\x00" + o.Package.Name
		}
	case ObjectRuntimePolicy:
		if o.RuntimePolicy != nil {
			return string(o.Kind) + "\x00" + o.RuntimePolicy.Name
		}
	}
	return ""
}

func objectPayloadPresent(o ObjectRecord) bool {
	switch o.Kind {
	case ObjectFile:
		return o.File != nil
	case ObjectFileMeta:
		return o.FileMeta != nil
	case ObjectService:
		return o.Service != nil
	case ObjectPackage:
		return o.Package != nil
	case ObjectRuntimePolicy:
		return o.RuntimePolicy != nil
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
	return FileModeFromOctal(uint32(parsed)), nil
}

// POSIX carries setuid, setgid and sticky in the 07000 range and os.FileMode carries them in high
// bits of its own. Every mode inside hardline is held in the os.FileMode spelling, so that a mode
// read off a host and a mode parsed from a profile are the same value when they mean the same thing.
func FileModeFromOctal(octal uint32) os.FileMode {
	mode := os.FileMode(octal) & os.ModePerm
	if octal&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if octal&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if octal&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

func FormatFileMode(mode os.FileMode) string {
	out := uint64(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		out |= 0o4000
	}
	if mode&os.ModeSetgid != 0 {
		out |= 0o2000
	}
	if mode&os.ModeSticky != 0 {
		out |= 0o1000
	}
	return strconv.FormatUint(out, 8)
}

func FirstLines(out string, n int) string {
	trimmed := strings.TrimSpace(out)
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "; ")
}

const (
	statProbePrefix     = "HL-STAT:"
	statProbeRCPrefix   = "HL-RC:"
	statErrorPrefix     = "stat: "
	statNotFoundSuffix  = "No such file or directory"
	maxProbeDetailBytes = 512
)

// complete is false when the probe reported no exit status, which is not the same as a stat that failed.
// notFound is stat's own ENOENT line for this exact path: a login shell that echoes the same wording stays
// in noise, so it cannot pass for a missing file and have rollback delete the file it is describing.
func parseStatProbe(out, remotePath string) (statLine string, rc int, notFound bool, noise []string, complete bool) {
	rc = -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case strings.HasPrefix(line, statProbePrefix):
			statLine = strings.TrimPrefix(line, statProbePrefix)
		case strings.HasPrefix(line, statProbeRCPrefix):
			code, err := strconv.Atoi(strings.TrimPrefix(line, statProbeRCPrefix))
			if err != nil {
				return "", -1, false, nil, false
			}
			rc = code
		case strings.HasPrefix(line, statErrorPrefix) && strings.HasSuffix(line, statNotFoundSuffix) &&
			strings.Contains(line, "'"+remotePath+"'"):
			notFound = true
		case line == "":
		default:
			noise = append(noise, line)
		}
	}
	if rc < 0 {
		return "", -1, false, nil, false
	}
	return statLine, rc, notFound, noise, true
}

func SnapshotRemoteFile(host Host, remotePath string) (FileSnapshot, error) {
	if host == nil {
		return FileSnapshot{}, fmt.Errorf("host is required")
	}

	snap := FileSnapshot{Path: remotePath}

	probe := "LC_ALL=C stat -c " + ShellArg(statProbePrefix+"%F|%a|%U|%G|%s") + " -- " +
		ShellArg(remotePath) + ` 2>&1; echo "` + statProbeRCPrefix + `$?"`
	probeOut, err := host.RunRootWithOutput(probe)
	if err != nil {
		return snap, fmt.Errorf("stat %q: %w", remotePath, err)
	}
	statLine, rc, notFound, noise, complete := parseStatProbe(probeOut, remotePath)
	if !complete {
		return snap, fmt.Errorf("stat %q: the probe did not report an exit status", remotePath)
	}
	if rc != 0 {
		if notFound {
			snap.Existed = false
			return snap, nil
		}
		detail := FirstLines(strings.Join(noise, "\n"), 3)
		if len(detail) > maxProbeDetailBytes {
			detail = strings.ToValidUTF8(detail[:maxProbeDetailBytes], "") + "..."
		}
		if detail == "" {
			return snap, fmt.Errorf("stat %q: exit status %d with no output", remotePath, rc)
		}
		return snap, fmt.Errorf("stat %q: exit status %d: %s", remotePath, rc, detail)
	}
	if statLine == "" {
		return snap, fmt.Errorf("stat %q: the probe succeeded but reported no file", remotePath)
	}

	fields := strings.Split(statLine, "|")
	if len(fields) != 5 {
		return snap, fmt.Errorf("parse stat output for %q: unexpected format %q", remotePath, statLine)
	}
	if fields[0] == "symbolic link" {
		return snap, fmt.Errorf("refusing to snapshot %q: it is a symlink", remotePath)
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
	if snap.Owner == "" || snap.Group == "" {
		return fmt.Errorf("restore file %q: the journal records no owner or group", snap.Path)
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

	if err := host.RunRoot("chown " + ShellArg(snap.Owner+":"+snap.Group) + " " + ShellArg(snap.Path)); err != nil {
		return fmt.Errorf("restore ownership of %q: %w", snap.Path, err)
	}
	if mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		if err := host.RunRoot("chmod " + ShellArg(FormatFileMode(mode)) + " " + ShellArg(snap.Path)); err != nil {
			return fmt.Errorf("restore mode of %q: %w", snap.Path, err)
		}
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
