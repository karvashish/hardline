package audit

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	loadCmd   = "augenrules --load"
	listCmd   = "auditctl -l"
	statusCmd = "auditctl -s"
)

func aligned(current pluginapi.FileSnapshot, rules []byte, mode os.FileMode) bool {
	return current.Existed &&
		current.ContentB64 == base64.StdEncoding.EncodeToString(rules) &&
		current.Mode == fmt.Sprintf("%o", mode.Perm())
}

func loadedRules(host pluginapi.Host) ([]Rule, error) {
	out, err := host.RunRootWithOutput(listCmd + " 2>/dev/null || true")
	if err != nil {
		return nil, fmt.Errorf("read loaded audit rules: %w", err)
	}
	if strings.Contains(out, "No rules") {
		return nil, nil
	}
	rules, skipped := ParseLoadedRules([]byte(out))
	for _, line := range skipped {
		logger.Debugf("audit: %s prints a rule this check cannot model, ignoring it: %q\n", listCmd, line)
	}
	return rules, nil
}

func assertPolicyMutable(host pluginapi.Host) error {
	out, err := host.RunRootWithOutput(statusCmd + " 2>/dev/null || true")
	if err != nil {
		return fmt.Errorf("read audit status: %w", err)
	}
	if auditEnabledLocked(out) {
		return fmt.Errorf("the host audit policy is locked (%s reports enabled 2); it cannot be changed until the host reboots", statusCmd)
	}
	return nil
}

func auditEnabledLocked(status string) bool {
	fields := strings.Fields(status)
	for i, field := range fields {
		if field == "enabled" && i+1 < len(fields) {
			return strings.TrimSpace(fields[i+1]) == "2"
		}
	}
	return false
}

func assertWatchPathsExist(host pluginapi.Host, rules []Rule) error {
	var missing []string
	for _, path := range WatchPaths(rules) {
		if err := host.RunRoot("test -e " + pluginapi.ShellArg(path)); err != nil {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("audit rules watch %d path(s) that do not exist on this host: %s; auditctl refuses those rules and the whole load fails with them",
			len(missing), strings.Join(missing, ", "))
	}
	return nil
}

func load(host pluginapi.Host, want []Rule) error {
	if err := host.RunRoot(loadCmd); err != nil {
		return fmt.Errorf("%s: %w", loadCmd, err)
	}
	loaded, err := loadedRules(host)
	if err != nil {
		return err
	}
	if missing := MissingRules(loaded, want); len(missing) > 0 {
		return fmt.Errorf("audit rules did not take effect: %s does not report %s",
			listCmd, describeRules(missing))
	}
	return nil
}

func describeRules(rules []Rule) string {
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		out = append(out, strconv.Quote(rule.String()))
	}
	return strings.Join(out, ", ")
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

	if err := AssertLoadableRules(rules); err != nil {
		return fmt.Errorf("audit rules %q: %w", spec.Src, err)
	}
	want, err := ParseRules(rules)
	if err != nil {
		return fmt.Errorf("audit rules %q: %w", spec.Src, err)
	}
	if len(want) == 0 {
		return fmt.Errorf("audit rules %q declare no rules, so a load cannot be verified", spec.Src)
	}
	if err := assertPolicyMutable(ctx.Host); err != nil {
		return err
	}
	if err := assertWatchPathsExist(ctx.Host, want); err != nil {
		return err
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

	loaded, err := loadedRules(ctx.Host)
	if err != nil {
		return err
	}
	if fileMatches && len(MissingRules(loaded, want)) == 0 {
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
	want, err := ParseRules(rules)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit rules %q: %w", spec.Src, err)
	}
	mode, err := pluginapi.ParseFileMode(spec.Mode)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("audit step: %w", err)
	}

	current, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Dest)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("read %s: %w", spec.Dest, err)
	}
	fileMatches := aligned(current, rules, mode)

	loaded, err := loadedRules(ctx.Host)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	missing := MissingRules(loaded, want)

	var details, diff, highlights []string

	if err := AssertLoadableRules(rules); err != nil {
		highlights = append(highlights, err.Error())
		details = append(details, logger.ColorRed+err.Error()+logger.ColorReset)
	}
	if err := assertPolicyMutable(ctx.Host); err != nil {
		highlights = append(highlights, err.Error())
		details = append(details, logger.ColorRed+err.Error()+logger.ColorReset)
	}
	if err := assertWatchPathsExist(ctx.Host, want); err != nil {
		highlights = append(highlights, err.Error())
		details = append(details, logger.ColorRed+err.Error()+logger.ColorReset)
	}

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
		details = append(details, fmt.Sprintf("%srunning policy already carries all %d rule(s)%s",
			logger.ColorBlue, len(want), logger.ColorReset))
	} else {
		details = append(details, fmt.Sprintf("%srunning policy is missing %d rule(s): %s%s",
			logger.ColorYellow, len(missing), describeRules(missing), logger.ColorReset))
		diff = append(diff, fmt.Sprintf("audit policy: %s would load %d missing rule(s)", loadCmd, len(missing)))
	}

	willChange := !fileMatches || len(missing) > 0
	summary := "audit step: rules file and running policy already aligned"
	operator := "Audit policy already matches the profile"
	if willChange {
		summary = fmt.Sprintf("audit step: write %s and run %s", spec.Dest, loadCmd)
		operator = fmt.Sprintf("Write the audit rules to %s and load them into the running kernel policy", spec.Dest)
	}

	return pluginapi.PlanResult{
		Summary:          summary,
		Details:          details,
		Diff:             diff,
		WillChange:       willChange,
		OperatorSummary:  operator,
		Highlights:       highlights,
		RollbackFidelity: pluginapi.ModeDeterministic,
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

func Restore(host pluginapi.Host, snap pluginapi.FileSnapshot) error {
	if host == nil {
		return fmt.Errorf("audit rollback: host is required")
	}
	if err := pluginapi.RestoreFileSnapshot(host, snap); err != nil {
		return err
	}

	if err := host.RunRoot(loadCmd); err != nil {
		return fmt.Errorf("%s after restoring %s: %w", loadCmd, snap.Path, err)
	}
	return nil
}
