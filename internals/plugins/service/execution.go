package service

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

func Apply(ctx pluginapi.Context, s *Spec) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if ctx.Host == nil {
		return fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(s.Name)
	logger.Debugf("handleService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, formatBoolPtr(s.Enabled), s.State)

	if s.Enabled != nil {
		enabledNow := serviceIsEnabled(ctx.Host, unit)
		if *s.Enabled != enabledNow {
			var cmd string
			if *s.Enabled {
				cmd = fmt.Sprintf("systemctl enable %s", strconv.Quote(unit))
			} else {
				cmd = fmt.Sprintf("systemctl disable %s", strconv.Quote(unit))
			}
			if err := ctx.Host.RunRoot(cmd); err != nil {
				return fmt.Errorf("systemctl enable/disable %s: %w", unit, err)
			}
		} else {
			logger.Debugf("handleService: enablement already matches for %s, skipping toggle\n", unit)
		}
	}

	state := strings.ToLower(strings.TrimSpace(s.State))
	if state == "" {
		return nil
	}

	var cmd string
	switch state {
	case "started", "start":
		if serviceIsActive(ctx.Host, unit) {
			logger.Debugf("handleService: %s already active, skipping start\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl start %s", strconv.Quote(unit))
	case "stopped", "stop":
		if !serviceIsActive(ctx.Host, unit) {
			logger.Debugf("handleService: %s already inactive, skipping stop\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl stop %s", strconv.Quote(unit))
	case "restarted", "restart":
		if restartPolicySuppressed(s, ctx.StepChanges, unit, ctx.Host) {
			logger.Debugf("handleService: %s skipping restart (restart_policy=on_change: no upstream change, service aligned)\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl restart %s", strconv.Quote(unit))
	case "reloaded", "reload", "reload-or-restart":
		if restartPolicySuppressed(s, ctx.StepChanges, unit, ctx.Host) {
			logger.Debugf("handleService: %s skipping reload (restart_policy=on_change: no upstream change, service aligned)\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl reload-or-restart %s", strconv.Quote(unit))
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := ctx.Host.RunRoot(cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}

	return nil
}

func Plan(ctx pluginapi.Context, s *Spec) (pluginapi.PlanResult, error) {
	if s.Name == "" {
		return pluginapi.PlanResult{Summary: "service step: invalid (missing service name)"}, fmt.Errorf("service name is required")
	}
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(s.Name)
	logger.Debugf("planService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, formatBoolPtr(s.Enabled), s.State)

	var details []string
	var diff []string
	var highlights []string

	enabledNow := serviceIsEnabled(ctx.Host, unit)
	enabledState := "unknown"
	if enabledNow {
		enabledState = "enabled"
	} else {
		enabledState = "disabled or not-found"
	}

	activeNow := serviceIsActive(ctx.Host, unit)
	activeState := "unknown"
	if activeNow {
		activeState = "active"
	} else {
		activeState = "inactive or not-found"
	}

	details = append(details,
		logger.ColorYellow+fmt.Sprintf("current: enabled=%s, active=%s", enabledState, activeState)+logger.ColorReset,
	)

	desiredEnabled := "unchanged"
	if s.Enabled != nil {
		if *s.Enabled {
			desiredEnabled = "enabled"
		} else {
			desiredEnabled = "disabled"
		}
		if *s.Enabled != enabledNow {
			diff = append(diff,
				fmt.Sprintf("service enablement: %s -> %s", enabledState, desiredEnabled),
			)
		}
	}
	state := strings.ToLower(strings.TrimSpace(s.State))
	desiredState := "unchanged"
	switch state {
	case "":

	case "started", "start":
		desiredState = "active"
		if !activeNow {
			diff = append(diff, fmt.Sprintf("service activity: %s -> active", activeState))
		}
	case "stopped", "stop":
		desiredState = "inactive"
		if activeNow {
			diff = append(diff, "service activity: active -> inactive")
		}
	case "restarted", "restart":
		desiredState = "restarted (active)"
		if restartPolicySuppressed(s, ctx.StepChanges, unit, ctx.Host) {
			desiredState = "active (restart skipped: restart_policy=on_change, no upstream change)"
		} else {
			diff = append(diff, fmt.Sprintf("service: restart %s (currently %s)", unit, activeState))
		}
	case "reloaded", "reload":
		desiredState = "reloaded or restarted (active)"
		if restartPolicySuppressed(s, ctx.StepChanges, unit, ctx.Host) {
			desiredState = "active (reload skipped: restart_policy=on_change, no upstream change)"
		} else {
			diff = append(diff, fmt.Sprintf("service: reload-or-restart %s (currently %s)", unit, activeState))
		}
	default:
		desiredState = fmt.Sprintf("unsupported (%q)", s.State)
		highlights = append(highlights, fmt.Sprintf("unsupported service state %q requested for %s", s.State, unit))
	}

	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: enabled=%s, state=%s", desiredEnabled, desiredState)+logger.ColorReset,
	)

	willChange := false
	if s.Enabled != nil {
		if (*s.Enabled && enabledState != "enabled") || (!*s.Enabled && enabledState != "disabled or not-found") {
			willChange = true
		}
	}
	switch state {
	case "":
	case "started", "start":
		willChange = willChange || activeState != "active"
	case "stopped", "stop":
		willChange = willChange || activeState != "inactive or not-found"
	case "restarted", "restart", "reloaded", "reload":
		if restartPolicySuppressed(s, ctx.StepChanges, unit, ctx.Host) {

		} else {
			willChange = true
		}
	default:
		willChange = true
	}

	var summaryParts []string
	if s.Enabled != nil {
		if *s.Enabled {
			summaryParts = append(summaryParts, fmt.Sprintf("enable %s at boot", unit))
		} else {
			summaryParts = append(summaryParts, fmt.Sprintf("disable %s at boot", unit))
		}
	}
	switch state {
	case "":

	case "started", "start":
		summaryParts = append(summaryParts, fmt.Sprintf("ensure %s is started", unit))
	case "stopped", "stop":
		summaryParts = append(summaryParts, fmt.Sprintf("ensure %s is stopped", unit))
	case "restarted", "restart":
		summaryParts = append(summaryParts, fmt.Sprintf("restart %s", unit))
	case "reloaded", "reload":
		summaryParts = append(summaryParts, fmt.Sprintf("reload or restart %s", unit))
	default:
		summaryParts = append(summaryParts, fmt.Sprintf("unsupported state %q requested for %s", s.State, unit))
	}

	var summary string
	var operatorSummary string
	if len(summaryParts) == 0 {
		summary = fmt.Sprintf("service step: no-op for %s (no enable/state change requested)", unit)
		operatorSummary = fmt.Sprintf("%s already matches the requested service state", unit)
	} else {
		summary = "service step: " + strings.Join(summaryParts, "; ")
		operatorSummary = serviceSentence(summaryParts)
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
		return record, fmt.Errorf("step %q (type=service): service spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(spec.Name)
	state, err := snapshotServiceState(ctx.Host, unit)
	if err != nil {
		return record, fmt.Errorf("capture service snapshot for %q: %w", unit, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectService, Service: &state},
	}
	record.Reload = serviceReloadRecord(spec)
	return record, nil
}

func serviceReloadRecord(spec *Spec) *pluginapi.ServiceReload {
	action := strings.ToLower(strings.TrimSpace(spec.State))
	if action == "" {
		return nil
	}
	reload := &pluginapi.ServiceReload{Action: action}
	if spec.RestartPolicy != nil {
		reload.RestartPolicy = strings.ToLower(strings.TrimSpace(spec.RestartPolicy.Type))
		if reload.RestartPolicy == "on_change" {
			reload.RestartDeps = append([]string(nil), spec.RestartPolicy.Steps...)
		}
	}
	return reload
}

func restartPolicySuppressed(s *Spec, stepChanges map[string]bool, unit string, host pluginapi.Host) bool {
	p := s.RestartPolicy
	if p == nil || p.Type == "always" {
		return false
	}

	for _, id := range p.Steps {
		if stepChanges[id] {
			return false
		}
	}

	if !serviceIsActive(host, unit) {
		return false
	}
	if s.Enabled != nil && *s.Enabled != serviceIsEnabled(host, unit) {
		return false
	}
	return true
}

func normalizeServiceUnit(unit string) string {
	name := strings.TrimSpace(unit)
	if name == "sshd" {
		return "ssh"
	}
	return name
}

func serviceIsEnabled(host pluginapi.Host, unit string) bool {
	if host == nil {
		return false
	}
	cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1", strconv.Quote(unit))
	return host.RunRoot(cmd) == nil
}

func serviceIsActive(host pluginapi.Host, unit string) bool {
	if host == nil {
		return false
	}
	cmd := fmt.Sprintf("systemctl is-active %s >/dev/null 2>&1", strconv.Quote(unit))
	return host.RunRoot(cmd) == nil
}

// serviceUnitPresent reports whether a unit fragment file exists. It uses
// systemctl cat, which reads the actual unit file: it produces output for a
// real unit and nothing when no fragment exists. is-enabled and is-active are
// unreliable here — purging a package removes its unit file but leaves the
// runtime enable symlink dangling, so is-enabled still reports a state and
// is-active still prints "inactive". Used to skip restoring a unit that no
// longer exists (e.g. its package was purged earlier in the same rollback).
func serviceUnitPresent(host pluginapi.Host, unit string) bool {
	if host == nil {
		return false
	}
	out, err := host.RunRootWithOutput("systemctl cat " + strconv.Quote(unit) + " 2>/dev/null || true")
	return err == nil && strings.TrimSpace(out) != ""
}

func snapshotServiceState(host pluginapi.Host, unit string) (pluginapi.ServiceState, error) {
	if host == nil {
		return pluginapi.ServiceState{}, fmt.Errorf("host is required")
	}

	enabledOut, err := host.RunRootWithOutput("systemctl is-enabled " + strconv.Quote(unit) + " 2>/dev/null || true")
	if err != nil {
		return pluginapi.ServiceState{}, err
	}

	activeOut, err := host.RunRootWithOutput("systemctl is-active " + strconv.Quote(unit) + " 2>/dev/null || true")
	if err != nil {
		return pluginapi.ServiceState{}, err
	}

	enabledVal := strings.TrimSpace(enabledOut)
	activeVal := strings.TrimSpace(activeOut)
	return pluginapi.ServiceState{
		Unit:    unit,
		Enabled: enabledVal == "enabled",
		Active:  activeVal == "active",
		Known:   enabledVal != "" || activeVal != "",
	}, nil
}

func restoreServiceState(host pluginapi.Host, state pluginapi.ServiceState) error {
	unit := strings.TrimSpace(state.Unit)
	if unit == "" {
		return fmt.Errorf("service unit is empty")
	}
	if !state.Known {
		return fmt.Errorf("service state for %q is unknown", unit)
	}

	if !serviceUnitPresent(host, unit) {
		return nil
	}

	enableCmd := "systemctl disable " + strconv.Quote(unit)
	if state.Enabled {
		enableCmd = "systemctl enable " + strconv.Quote(unit)
	}
	if err := host.RunRoot(enableCmd); err != nil {
		return fmt.Errorf("restore service enabled state for %q: %w", unit, err)
	}

	activeCmd := "systemctl stop " + strconv.Quote(unit)
	if state.Active {
		activeCmd = "systemctl restart " + strconv.Quote(unit)
	}
	if err := host.RunRoot(activeCmd); err != nil {
		return fmt.Errorf("restore service active state for %q: %w", unit, err)
	}
	return nil
}

func serviceStateConflict(host pluginapi.Host, state pluginapi.ServiceState) []string {
	if !state.Known {
		return nil
	}
	unit := strings.TrimSpace(state.Unit)
	if unit == "" {
		return nil
	}
	current, err := snapshotServiceState(host, unit)
	if err != nil {
		return nil
	}
	var conflicts []string
	if current.Enabled != state.Enabled {
		conflicts = append(conflicts, fmt.Sprintf("service %q: enabled state is %v but journal recorded %v after apply (changed since apply)", unit, current.Enabled, state.Enabled))
	}
	if current.Active != state.Active {
		conflicts = append(conflicts, fmt.Sprintf("service %q: active state is %v but journal recorded %v after apply (changed since apply)", unit, current.Active, state.Active))
	}
	return conflicts
}

func formatBoolPtr(b *bool) string {
	if b == nil {
		return "nil"
	}
	if *b {
		return "true"
	}
	return "false"
}

func serviceSentence(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	text := strings.Join(parts, "; ")
	return strings.ToUpper(text[:1]) + text[1:]
}
