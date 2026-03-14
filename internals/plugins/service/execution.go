package service

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/rollbackutil"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

func Apply(ctx pluginapi.ApplyContext, s *Spec) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if ctx.Host == nil {
		return fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(s.Name)
	logger.Debugf("handleService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, s.Enabled, s.State)

	if s.Enabled != nil {
		enabledNow := serviceIsEnabled(ctx.Host, unit)
		if *s.Enabled != enabledNow {
			var cmd string
			if *s.Enabled {
				cmd = fmt.Sprintf("systemctl enable %s", unit)
			} else {
				cmd = fmt.Sprintf("systemctl disable %s", unit)
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
		cmd = fmt.Sprintf("systemctl start %s", unit)
	case "stopped", "stop":
		if !serviceIsActive(ctx.Host, unit) {
			logger.Debugf("handleService: %s already inactive, skipping stop\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl stop %s", unit)
	case "restarted", "restart":
		cmd = fmt.Sprintf("systemctl restart %s", unit)
	case "reloaded", "reload", "reload-or-restart":
		cmd = fmt.Sprintf("systemctl reload-or-restart %s", unit)
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := ctx.Host.RunRoot(cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}

	return nil
}

func Plan(ctx pluginapi.PlanContext, s *Spec) (pluginapi.PlanResult, error) {
	if s.Name == "" {
		return pluginapi.PlanResult{Summary: "service step: invalid (missing service name)"}, fmt.Errorf("service name is required")
	}
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(s.Name)
	logger.Debugf("planService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, s.Enabled, s.State)

	var details []string

	enabledState := "unknown"
	if serviceIsEnabled(ctx.Host, unit) {
		enabledState = "enabled"
	} else {
		enabledState = "disabled or not-found"
	}

	activeState := "unknown"
	if serviceIsActive(ctx.Host, unit) {
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
	}
	state := strings.ToLower(strings.TrimSpace(s.State))
	desiredState := "unchanged"
	switch state {
	case "":

	case "started", "start":
		desiredState = "active"
	case "stopped", "stop":
		desiredState = "inactive"
	case "restarted", "restart":
		desiredState = "restarted (active)"
	case "reloaded", "reload":
		desiredState = "reloaded or restarted (active)"
	default:
		desiredState = fmt.Sprintf("unsupported (%q)", s.State)
	}

	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: enabled=%s, state=%s", desiredEnabled, desiredState)+logger.ColorReset,
	)

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
	if len(summaryParts) == 0 {
		summary = fmt.Sprintf("service step: no-op for %s (no enable/state change requested)", unit)
	} else {
		summary = "service step: " + strings.Join(summaryParts, "; ")
	}

	return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
}

func CaptureRollback(ctx pluginapi.RollbackContext, stepID string, spec *Spec) (rollback.StepRecord, error) {
	record := rollback.StepRecord{
		ID:   stepID,
		Type: "service",
	}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=service): service spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("service step: host context is required")
	}

	unit := normalizeServiceUnit(spec.Name)
	state, err := rollbackutil.SnapshotServiceState(ctx.Host, unit)
	if err != nil {
		return record, fmt.Errorf("capture service snapshot for %q: %w", unit, err)
	}

	record.RollbackMode = rollback.ModeDeterministic
	record.Objects = []rollback.ObjectRecord{
		{Kind: rollback.ObjectService, Service: &state},
	}
	return record, nil
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
	cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1", unit)
	return host.RunRoot(cmd) == nil
}

func serviceIsActive(host pluginapi.Host, unit string) bool {
	if host == nil {
		return false
	}
	cmd := fmt.Sprintf("systemctl is-active %s >/dev/null 2>&1", unit)
	return host.RunRoot(cmd) == nil
}
