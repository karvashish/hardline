package filemeta

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

func Apply(ctx pluginapi.Context, s *Spec) error {
	if ctx.Host == nil {
		return fmt.Errorf("file_meta step: host context is required")
	}
	target, err := enforceAbsCleanPath(s.Path)
	if err != nil {
		return fmt.Errorf("file_meta apply: %w", err)
	}
	logger.Debugf("handleFileMeta: path=%q mode=%q owner=%q group=%q immutable=%v append_only=%v\n",
		target, s.Mode, s.Owner, s.Group, s.Immutable, s.AppendOnly)

	cur, err := snapshotFileMeta(ctx.Host, target)
	if err != nil {
		return fmt.Errorf("inspect %q: %w", target, err)
	}
	if !cur.Existed {
		return fmt.Errorf("file_meta apply: target %q does not exist (file_meta never creates files)", target)
	}

	desiredMode := cur.Mode
	if strings.TrimSpace(s.Mode) != "" {
		desiredMode, err = normalizeMode(s.Mode)
		if err != nil {
			return fmt.Errorf("file_meta apply: %w", err)
		}
	}
	desiredOwner := cur.Owner
	if strings.TrimSpace(s.Owner) != "" {
		desiredOwner = strings.TrimSpace(s.Owner)
	}
	desiredGroup := cur.Group
	if strings.TrimSpace(s.Group) != "" {
		desiredGroup = strings.TrimSpace(s.Group)
	}
	manageAttrs := s.Immutable != nil || s.AppendOnly != nil
	desiredAttrs := cur.Attrs
	if manageAttrs {
		desiredAttrs = desiredManagedAttrs(cur.Attrs, s)
	}

	modeChange := strings.TrimSpace(s.Mode) != "" && desiredMode != cur.Mode
	ownerChange := (strings.TrimSpace(s.Owner) != "" || strings.TrimSpace(s.Group) != "") &&
		(desiredOwner != cur.Owner || desiredGroup != cur.Group)
	attrChange := manageAttrs && desiredAttrs != cur.Attrs

	if !modeChange && !ownerChange && !attrChange {
		logger.Debugf("handleFileMeta: %q already matches desired metadata, skipping\n", target)
		return nil
	}

	runRoot := ctx.Host.RunRoot

	// An immutable file rejects chmod/chown; lift managed attrs first when we own them.
	cleared := false
	if (modeChange || ownerChange) && manageAttrs && cur.Attrs != "" {
		if err := applyManagedAttrs(runRoot, target, ""); err != nil {
			return err
		}
		cleared = true
	}

	if modeChange {
		if err := runRoot("chmod " + strconv.Quote(desiredMode) + " -- " + strconv.Quote(target)); err != nil {
			return fmt.Errorf("chmod %q: %w", target, err)
		}
	}
	if ownerChange {
		if err := runRoot("chown " + strconv.Quote(chownArg(s)) + " -- " + strconv.Quote(target)); err != nil {
			return fmt.Errorf("chown %q: %w", target, err)
		}
	}
	if manageAttrs && (attrChange || cleared) {
		if err := applyManagedAttrs(runRoot, target, desiredAttrs); err != nil {
			return err
		}
	}
	return nil
}

func Plan(ctx pluginapi.Context, s *Spec) (pluginapi.PlanResult, error) {
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("file_meta step: host context is required")
	}
	target, err := enforceAbsCleanPath(s.Path)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("file_meta plan: %w", err)
	}
	logger.Debugf("planFileMeta: path=%q mode=%q owner=%q group=%q\n", target, s.Mode, s.Owner, s.Group)

	cur, err := snapshotFileMeta(ctx.Host, target)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("inspect %q: %w", target, err)
	}

	var details, diff, highlights []string

	if !cur.Existed {
		highlights = append(highlights, fmt.Sprintf("target %q does not exist; apply will fail (file_meta never creates files)", target))
		details = append(details, logger.ColorRed+fmt.Sprintf("target %q does not exist", target)+logger.ColorReset)
		return pluginapi.PlanResult{
			Summary:         fmt.Sprintf("file_meta step: target %q is absent (apply will fail)", target),
			Details:         details,
			WillChange:      false,
			OperatorSummary: fmt.Sprintf("%q does not exist; file_meta cannot stamp metadata on a missing path", target),
			Highlights:      highlights,
		}, nil
	}

	desiredMode := cur.Mode
	if strings.TrimSpace(s.Mode) != "" {
		desiredMode, err = normalizeMode(s.Mode)
		if err != nil {
			return pluginapi.PlanResult{}, fmt.Errorf("file_meta plan: %w", err)
		}
	}
	desiredOwner := cur.Owner
	if strings.TrimSpace(s.Owner) != "" {
		desiredOwner = strings.TrimSpace(s.Owner)
	}
	desiredGroup := cur.Group
	if strings.TrimSpace(s.Group) != "" {
		desiredGroup = strings.TrimSpace(s.Group)
	}
	manageAttrs := s.Immutable != nil || s.AppendOnly != nil
	desiredAttrs := cur.Attrs
	if manageAttrs {
		desiredAttrs = desiredManagedAttrs(cur.Attrs, s)
	}

	details = append(details,
		logger.ColorYellow+fmt.Sprintf("current: mode=%s owner=%s group=%s attrs=%q", cur.Mode, cur.Owner, cur.Group, cur.Attrs)+logger.ColorReset,
		logger.ColorGreen+fmt.Sprintf("desired: mode=%s owner=%s group=%s attrs=%q", desiredMode, desiredOwner, desiredGroup, desiredAttrs)+logger.ColorReset,
	)

	if strings.TrimSpace(s.Mode) != "" && desiredMode != cur.Mode {
		diff = append(diff, fmt.Sprintf("mode %q: %s -> %s", target, cur.Mode, desiredMode))
	}
	if strings.TrimSpace(s.Owner) != "" && desiredOwner != cur.Owner {
		diff = append(diff, fmt.Sprintf("owner %q: %s -> %s", target, cur.Owner, desiredOwner))
	}
	if strings.TrimSpace(s.Group) != "" && desiredGroup != cur.Group {
		diff = append(diff, fmt.Sprintf("group %q: %s -> %s", target, cur.Group, desiredGroup))
	}
	if manageAttrs && desiredAttrs != cur.Attrs {
		diff = append(diff, fmt.Sprintf("attrs %q: %q -> %q", target, cur.Attrs, desiredAttrs))
	}

	willChange := len(diff) > 0
	summary := fmt.Sprintf("file_meta step: re-stamp metadata on %q", target)
	operatorSummary := fmt.Sprintf("Set metadata on %q (mode=%s owner=%s group=%s attrs=%q)", target, desiredMode, desiredOwner, desiredGroup, desiredAttrs)
	if !willChange {
		summary = fmt.Sprintf("file_meta step: no change required for %q (metadata already matches)", target)
		operatorSummary = fmt.Sprintf("%q already has the desired metadata", target)
	}

	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		WillChange:      willChange,
		OperatorSummary: operatorSummary,
		Highlights:      highlights,
	}, nil
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=file_meta): file_meta spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("file_meta step: host context is required")
	}

	target, err := enforceAbsCleanPath(spec.Path)
	if err != nil {
		return record, fmt.Errorf("step %q (type=file_meta): %w", stepID, err)
	}

	snap, err := snapshotFileMeta(ctx.Host, target)
	if err != nil {
		return record, fmt.Errorf("capture file_meta snapshot for %q: %w", target, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectFileMeta, FileMeta: &snap},
	}
	return record, nil
}

// restoreFileMeta reverts mode/owner/group/managed-attrs to the captured
// snapshot. It never creates the path: an absent snapshot is a no-op and a
// since-deleted target is an error. Managed attrs are cleared first so an
// immutable target does not reject chmod/chown.
func restoreFileMeta(host pluginapi.Host, snap pluginapi.FileMetaSnapshot) error {
	if _, err := enforceAbsCleanPath(snap.Path); err != nil {
		return err
	}
	if !snap.Existed {
		return nil
	}
	if host == nil {
		return fmt.Errorf("host is required")
	}
	if err := host.RunRoot("test -e " + strconv.Quote(snap.Path)); err != nil {
		return fmt.Errorf("restore file metadata for %q: path no longer exists", snap.Path)
	}

	if err := applyManagedAttrs(host.RunRoot, snap.Path, ""); err != nil {
		return err
	}
	if strings.TrimSpace(snap.Mode) != "" {
		if err := host.RunRoot("chmod " + strconv.Quote(snap.Mode) + " -- " + strconv.Quote(snap.Path)); err != nil {
			return fmt.Errorf("restore mode for %q: %w", snap.Path, err)
		}
	}
	if strings.TrimSpace(snap.Owner) != "" || strings.TrimSpace(snap.Group) != "" {
		ownerSpec := strings.TrimSpace(snap.Owner) + ":" + strings.TrimSpace(snap.Group)
		if err := host.RunRoot("chown " + strconv.Quote(ownerSpec) + " -- " + strconv.Quote(snap.Path)); err != nil {
			return fmt.Errorf("restore owner/group for %q: %w", snap.Path, err)
		}
	}
	return applyManagedAttrs(host.RunRoot, snap.Path, snap.Attrs)
}

// fileMetaConflict reports whether the path drifted from the post-apply
// metadata recorded in after. An empty result means no conflict.
func fileMetaConflict(host pluginapi.Host, after pluginapi.FileMetaSnapshot) []string {
	if !after.Existed {
		return nil
	}
	current, err := snapshotFileMeta(host, after.Path)
	if err != nil {
		return []string{fmt.Sprintf("%s: journal expects path to exist but its metadata cannot be read (%v)", after.Path, err)}
	}
	if !current.Existed {
		return []string{fmt.Sprintf("%s: journal expects path to exist but it is now absent (changed since apply)", after.Path)}
	}
	if current.Mode != after.Mode || current.Owner != after.Owner || current.Group != after.Group || current.Attrs != after.Attrs {
		return []string{fmt.Sprintf("%s: metadata (mode/owner/group/attrs) differs from what this profile set (modified since apply)", after.Path)}
	}
	return nil
}

func desiredManagedAttrs(curAttrs string, s *Spec) string {
	hasA := strings.IndexByte(curAttrs, 'a') >= 0
	hasI := strings.IndexByte(curAttrs, 'i') >= 0
	if s.AppendOnly != nil {
		hasA = *s.AppendOnly
	}
	if s.Immutable != nil {
		hasI = *s.Immutable
	}
	var out []byte
	if hasA {
		out = append(out, 'a')
	}
	if hasI {
		out = append(out, 'i')
	}
	return string(out)
}

func chownArg(s *Spec) string {
	owner := strings.TrimSpace(s.Owner)
	group := strings.TrimSpace(s.Group)
	switch {
	case owner != "" && group != "":
		return owner + ":" + group
	case owner != "":
		return owner
	case group != "":
		return ":" + group
	default:
		return ""
	}
}

// normalizeMode reformats an octal mode to the form `stat -c %a` emits, so
// "0640" compares equal to the host's "640".
func normalizeMode(mode string) (string, error) {
	t := strings.TrimSpace(mode)
	if t == "" {
		return "", nil
	}
	parsed, err := strconv.ParseUint(t, 8, 32)
	if err != nil {
		return "", fmt.Errorf("invalid octal mode %q", mode)
	}
	return strconv.FormatUint(parsed, 8), nil
}

// snapshotFileMeta records mode/owner/group/managed-attrs for a path. A missing
// path yields Existed=false and no error.
func snapshotFileMeta(host pluginapi.Host, target string) (pluginapi.FileMetaSnapshot, error) {
	if host == nil {
		return pluginapi.FileMetaSnapshot{}, fmt.Errorf("host is required")
	}

	snap := pluginapi.FileMetaSnapshot{Path: target}
	if err := host.RunRoot("test -e " + strconv.Quote(target)); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	out, err := host.RunRootWithOutput("stat -c '%a %U %G' -- " + strconv.Quote(target))
	if err != nil {
		return snap, err
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 3 {
		return snap, fmt.Errorf("parse stat output for %q: unexpected format %q", target, strings.TrimSpace(out))
	}
	snap.Mode = fields[0]
	snap.Owner = fields[1]
	snap.Group = fields[2]

	attrs, err := readManagedAttrs(host, target)
	if err != nil {
		return snap, err
	}
	snap.Attrs = attrs
	return snap, nil
}

func readManagedAttrs(host pluginapi.Host, target string) (string, error) {
	out, err := host.RunRootWithOutput("lsattr -d -- " + strconv.Quote(target))
	if err != nil {
		return "", fmt.Errorf("read attrs for %q: %w", target, err)
	}
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) == 0 {
		return "", nil
	}
	flags := fields[0]
	var present []byte
	for i := 0; i < len(managedAttrLetters); i++ {
		c := managedAttrLetters[i]
		if strings.IndexByte(flags, c) >= 0 {
			present = append(present, c)
		}
	}
	return string(present), nil
}

// managedAttrLetters bounds file_meta to the 'a' (append-only) and 'i'
// (immutable) chattr flags; attrs outside this set are never touched.
const managedAttrLetters = "ai"

// enforceAbsCleanPath canonicalizes the target of a root-executed step from a
// signed profile. It requires printable ASCII with no whitespace or control
// characters — a NUL/newline/CR breaks command construction and a unicode
// homoglyph spoofs review — then an absolute, non-root, normalized path. A
// trailing slash is tolerated; .. and // are rejected so the path stays literal.
func enforceAbsCleanPath(target string) (string, error) {
	if target == "" {
		return "", fmt.Errorf("target path is empty")
	}
	for i := 0; i < len(target); i++ {
		if target[i] < 0x21 || target[i] > 0x7e {
			return "", fmt.Errorf("target %q must be printable ASCII with no whitespace or control characters", target)
		}
	}
	if !strings.HasPrefix(target, "/") {
		return "", fmt.Errorf("target %q is not an absolute path", target)
	}
	p := target
	if p != "/" {
		p = strings.TrimRight(p, "/")
	}
	if p == "" || p == "/" {
		return "", fmt.Errorf("target %q refers to the filesystem root", target)
	}
	if path.Clean(p) != p {
		return "", fmt.Errorf("target %q is not a normalized path", target)
	}
	return p, nil
}

// applyManagedAttrs drives target's managed chattr flags to exactly desired,
// never touching letters outside managedAttrLetters.
func applyManagedAttrs(runRoot func(string) error, target, desired string) error {
	var set, clear []byte
	for i := 0; i < len(managedAttrLetters); i++ {
		c := managedAttrLetters[i]
		if strings.IndexByte(desired, c) >= 0 {
			set = append(set, c)
		} else {
			clear = append(clear, c)
		}
	}
	if len(clear) > 0 {
		if err := runRoot("chattr -" + string(clear) + " -- " + strconv.Quote(target)); err != nil {
			return fmt.Errorf("clear attrs %q on %q: %w", string(clear), target, err)
		}
	}
	if len(set) > 0 {
		if err := runRoot("chattr +" + string(set) + " -- " + strconv.Quote(target)); err != nil {
			return fmt.Errorf("set attrs %q on %q: %w", string(set), target, err)
		}
	}
	return nil
}
