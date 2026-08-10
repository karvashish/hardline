package audit

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	loadCmd = "augenrules --load"
	listCmd = "auditctl -l"
)

// ruleKeyPattern pulls the keys out of a rules file or out of auditctl output.
// Those keys are what lets apply confirm the kernel is running this policy
// rather than trusting that the write succeeded. Both spellings have to match:
// a rules file writes -k, and auditctl -l renders the key of a syscall rule as
// the field it actually is, "-F key=name", keeping -k only for watches.
var ruleKeyPattern = regexp.MustCompile(`(?m)(?:-k[= ]|-F +key=)([A-Za-z0-9_.:-]+)`)

// RuleKeys is the sorted, deduplicated set of rule keys in a rules file.
func RuleKeys(rules []byte) []string {
	seen := map[string]struct{}{}
	for _, m := range ruleKeyPattern.FindAllSubmatch(rules, -1) {
		seen[string(m[1])] = struct{}{}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// aligned reports whether dest already carries the rendered rules at the
// declared mode. Mode counts as much as content: the right bytes at 0666 are
// an audit policy any unprivileged user can rewrite.
func aligned(current pluginapi.FileSnapshot, rules []byte, mode os.FileMode) bool {
	return current.Existed &&
		current.ContentB64 == base64.StdEncoding.EncodeToString(rules) &&
		current.Mode == fmt.Sprintf("%o", mode.Perm())
}

// loadedKeys reports which keys the running kernel policy currently carries.
// An audit subsystem that is disabled or has no rules is not an error here; it
// is simply an empty set, which is what makes apply decide to load.
func loadedKeys(host pluginapi.Host) (map[string]struct{}, error) {
	out, err := host.RunRootWithOutput(listCmd + " 2>/dev/null || true")
	if err != nil {
		return nil, fmt.Errorf("read loaded audit rules: %w", err)
	}
	keys := map[string]struct{}{}
	for _, key := range RuleKeys([]byte(out)) {
		keys[key] = struct{}{}
	}
	return keys, nil
}

func missingKeys(loaded map[string]struct{}, want []string) []string {
	var missing []string
	for _, key := range want {
		if _, ok := loaded[key]; !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

// load compiles rules.d and installs the result into the kernel, then reads the
// policy back. augenrules is the control path RHEL documents; auditctl is the
// only thing that proves the rules are live rather than merely on disk.
func load(host pluginapi.Host, want []string) error {
	if err := host.RunRoot(loadCmd); err != nil {
		return fmt.Errorf("%s: %w", loadCmd, err)
	}
	loaded, err := loadedKeys(host)
	if err != nil {
		return err
	}
	if missing := missingKeys(loaded, want); len(missing) > 0 {
		return fmt.Errorf("audit rules did not take effect: %s reports no rules for %s",
			listCmd, strings.Join(missing, ", "))
	}
	return nil
}

func Apply(ctx pluginapi.Context, spec *Spec) error {
	logger.Debugf("handleAudit: src=%q dest=%q\n", spec.Src, spec.Dest)
	if ctx.Profile == nil {
		return fmt.Errorf("audit step: profile context is required")
	}
	if ctx.Host == nil {
		return fmt.Errorf("audit step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Dest); err != nil {
		return fmt.Errorf("audit apply: %w", err)
	}

	rules, err := ctx.Profile.LoadTemplate(spec.Src)
	if err != nil {
		return fmt.Errorf("load audit rules %q: %w", spec.Src, err)
	}
	mode, err := pluginapi.ParseFileMode(spec.Mode)
	if err != nil {
		return fmt.Errorf("audit step: %w", err)
	}

	want := RuleKeys(rules)
	if len(want) == 0 {
		return fmt.Errorf("audit rules %q declare no -k keys, so a load cannot be verified", spec.Src)
	}

	current, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Dest)
	if err != nil {
		return fmt.Errorf("read %s: %w", spec.Dest, err)
	}
	fileMatches := aligned(current, rules, mode)
	if !fileMatches {
		if err := ctx.Host.WriteRootFile(spec.Dest, rules, mode); err != nil {
			return fmt.Errorf("write %s: %w", spec.Dest, err)
		}
	}

	// Reload when the file changed, and also when the file was already correct
	// but the kernel is not running it: a rules file on disk that was never
	// loaded is the exact failure this plugin exists to prevent.
	loaded, err := loadedKeys(ctx.Host)
	if err != nil {
		return err
	}
	if fileMatches && len(missingKeys(loaded, want)) == 0 {
		logger.Debugf("handleAudit: %s already loaded, skipping %s\n", spec.Dest, loadCmd)
		return nil
	}
	return load(ctx.Host, want)
}

func Plan(ctx pluginapi.Context, spec *Spec) (pluginapi.PlanResult, error) {
	if ctx.Profile == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit step: profile context is required")
	}
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Dest); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit plan: %w", err)
	}

	rules, err := ctx.Profile.LoadTemplate(spec.Src)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("load audit rules %q: %w", spec.Src, err)
	}
	want := RuleKeys(rules)
	mode, err := pluginapi.ParseFileMode(spec.Mode)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit step: %w", err)
	}

	current, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Dest)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("read %s: %w", spec.Dest, err)
	}
	fileMatches := aligned(current, rules, mode)

	loaded, err := loadedKeys(ctx.Host)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	missing := missingKeys(loaded, want)

	var details, diff []string
	if fileMatches {
		details = append(details, fmt.Sprintf("%s%s: already matches%s", logger.ColorBlue, spec.Dest, logger.ColorReset))
	} else {
		verb := "rewritten"
		if !current.Existed {
			verb = "created"
		}
		details = append(details, fmt.Sprintf("%s%s: will be %s from %q%s",
			logger.ColorGreen, spec.Dest, verb, spec.Src, logger.ColorReset))
		diff = append(diff, fmt.Sprintf("file %q: %s -> rendered audit rules", spec.Dest, verb))
	}

	if len(missing) == 0 {
		details = append(details, fmt.Sprintf("%srunning policy already carries every rule key (%s)%s",
			logger.ColorBlue, strings.Join(want, ", "), logger.ColorReset))
	} else {
		details = append(details, fmt.Sprintf("%srunning policy is missing %d rule key(s): %s%s",
			logger.ColorYellow, len(missing), strings.Join(missing, ", "), logger.ColorReset))
		diff = append(diff, fmt.Sprintf("audit policy: %s would load %d missing rule key(s)", loadCmd, len(missing)))
	}

	willChange := !fileMatches || len(missing) > 0
	summary := "audit step: rules file and running policy already aligned"
	operator := "Audit policy already matches the profile"
	if willChange {
		summary = fmt.Sprintf("audit step: write %s and run %s", spec.Dest, loadCmd)
		operator = fmt.Sprintf("Write the audit rules to %s and load them into the running kernel policy", spec.Dest)
	}

	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		WillChange:      willChange,
		OperatorSummary: operator,
	}, nil
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if ctx.Host == nil {
		return record, fmt.Errorf("audit step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Dest); err != nil {
		return record, fmt.Errorf("step %q (type=audit): %w", stepID, err)
	}

	snap, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Dest)
	if err != nil {
		return record, fmt.Errorf("capture audit rules for %q: %w", spec.Dest, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{{Kind: pluginapi.ObjectFile, File: &snap}}
	return record, nil
}

// Restore puts the rules file back and reloads it in one operation. Rollback
// walks steps in reverse, so a separate reload step would run before the file
// it depends on had been restored; keeping both here is what makes the
// rollback leave the kernel running the rules that are actually on disk.
func Restore(host pluginapi.Host, snap pluginapi.FileSnapshot) error {
	if host == nil {
		return fmt.Errorf("audit rollback: host is required")
	}
	if err := pluginapi.RestoreFileSnapshot(host, snap); err != nil {
		return err
	}

	// After a restore the previous rules are authoritative, whatever they were.
	// Their keys are unknown here, so the reload is not key-verified; a failure
	// to reload is still reported.
	if err := host.RunRoot(loadCmd); err != nil {
		return fmt.Errorf("%s after restoring %s: %w", loadCmd, snap.Path, err)
	}
	return nil
}
