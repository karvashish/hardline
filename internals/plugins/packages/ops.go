package packages

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	StateDir            = "/var/lib/hardline"
	StateLastUpdate     = "/var/lib/hardline/last-update"
	StateLastUpgrade    = "/var/lib/hardline/last-upgrade"
	StateLastAutoremove = "/var/lib/hardline/last-autoremove"
)

func ParseSinceDuration(s string) (time.Duration, error) {
	if !strings.HasPrefix(s, "if_") || !strings.HasSuffix(s, "_since_last") {
		return 0, fmt.Errorf("expected if_<N>[hdw]_since_last format, got %q", s)
	}
	inner := strings.TrimPrefix(strings.TrimSuffix(s, "_since_last"), "if_")
	if len(inner) < 2 {
		return 0, fmt.Errorf("missing value in %q", s)
	}
	unit := inner[len(inner)-1]
	n, err := strconv.Atoi(inner[:len(inner)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid count in %q", s)
	}
	switch unit {
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown unit %q in %q (use h, d, or w)", string(unit), s)
	}
}

func ValidateOpMode(field, mode string) error {
	switch mode {
	case "", "never", "always", "once":
		return nil
	default:
		if _, err := ParseSinceDuration(mode); err != nil {
			return fmt.Errorf("packages %s: invalid value %q (use always, once, never, or if_<N>[hdw]_since_last): %w", field, mode, err)
		}
		return nil
	}
}

func ShouldRun(host pluginapi.Host, mode, stateFile string, wouldChange bool) (bool, error) {
	switch mode {
	case "", "never":
		return false, nil
	case "always":
		return true, nil
	case "once":
		return wouldChange, nil
	default:
		dur, err := ParseSinceDuration(mode)
		if err != nil {
			return false, err
		}
		info, statErr := host.Stat(stateFile)
		if statErr != nil {
			return true, nil
		}
		return time.Since(info.ModTime()) >= dur, nil
	}
}

func MarkRan(host pluginapi.Host, stateFile string) {
	if err := host.RunRoot("mkdir -p " + StateDir); err != nil {
		logger.Warnf("packages: could not create state dir %q: %v\n", StateDir, err)
		return
	}
	if err := host.WriteRootFile(stateFile, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		logger.Warnf("packages: could not write state file %q: %v\n", stateFile, err)
	}
}

// Decision is one operation's run/skip verdict and the reason plan prints for it.
type Decision struct {
	WillRun bool
	Reason  string
}

func PlanOpDecision(host pluginapi.Host, mode, stateFile string, wouldChange bool) (Decision, error) {
	switch mode {
	case "", "never":
		return Decision{false, ""}, nil
	case "always":
		return Decision{true, "always"}, nil
	case "once":
		if wouldChange {
			return Decision{true, "once: packages need to change"}, nil
		}
		return Decision{false, "once: packages already aligned"}, nil
	default:
		dur, err := ParseSinceDuration(mode)
		if err != nil {
			return Decision{}, err
		}
		info, statErr := host.Stat(stateFile)
		if statErr != nil {
			return Decision{true, "never ran"}, nil
		}
		elapsed := time.Since(info.ModTime())
		if elapsed >= dur {
			return Decision{true, fmt.Sprintf("last ran %s ago, threshold %s", FormatElapsed(elapsed), mode)}, nil
		}
		remaining := dur - elapsed
		return Decision{false, fmt.Sprintf("ran %s ago, threshold %s (next run in ~%s)", FormatElapsed(elapsed), mode, FormatElapsed(remaining))}, nil
	}
}

func FormatElapsed(d time.Duration) string {
	if d >= 7*24*time.Hour {
		return fmt.Sprintf("%dw", int(d/(7*24*time.Hour)))
	}
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	}
	if d >= time.Hour {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

// NeedsWouldChange reports whether any op mode is "once", which is the only
// mode whose decision depends on the current package state.
func NeedsWouldChange(update, upgrade, autoremove string) bool {
	return update == "once" || upgrade == "once" || autoremove == "once"
}
