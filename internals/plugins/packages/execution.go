package packages

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	stateDir            = "/var/lib/hardline"
	stateLastUpdate     = "/var/lib/hardline/last-update"
	stateLastUpgrade    = "/var/lib/hardline/last-upgrade"
	stateLastAutoremove = "/var/lib/hardline/last-autoremove"

	// aptTimeoutSeconds is the per-command deadline applied to all apt-get
	// invocations via the shell timeout(1) utility. This prevents wedged
	// package operations from blocking automation indefinitely.
	aptTimeoutSeconds = 1800 // 30 minutes
)

// aptSSHTimeout is the SSH session deadline for apt commands. It must exceed
// aptTimeoutSeconds so the shell-level timeout fires first and returns a
// meaningful error; the SSH deadline is the outer safety net.
var aptSSHTimeout = time.Duration(aptTimeoutSeconds)*time.Second + 5*time.Minute

func aptRunRoot(host pluginapi.Host, cmd string) error {
	_, err := host.RunRootWithTimeout(cmd, aptSSHTimeout)
	return err
}

var validPackageName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.+-]*$`)

func validatePackageNames(names []string) error {
	for _, name := range names {
		if !validPackageName.MatchString(name) {
			return fmt.Errorf("invalid package name %q: must match %s", name, validPackageName.String())
		}
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func parseSinceDuration(s string) (time.Duration, error) {
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

func validateOpMode(field, mode string) error {
	switch mode {
	case "", "never", "always", "once":
		return nil
	default:
		if _, err := parseSinceDuration(mode); err != nil {
			return fmt.Errorf("packages %s: invalid value %q (use always, once, never, or if_<N>[hdw]_since_last): %w", field, mode, err)
		}
		return nil
	}
}

func shouldRun(host pluginapi.Host, mode, stateFile string, wouldChange bool) (bool, error) {
	switch mode {
	case "", "never":
		return false, nil
	case "always":
		return true, nil
	case "once":
		return wouldChange, nil
	default:
		dur, err := parseSinceDuration(mode)
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

func markRan(host pluginapi.Host, stateFile string) {
	if err := host.RunRoot("mkdir -p " + stateDir); err != nil {
		logger.Warnf("packages: could not create state dir %q: %v\n", stateDir, err)
		return
	}
	if err := host.WriteRootFile(stateFile, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		logger.Warnf("packages: could not write state file %q: %v\n", stateFile, err)
	}
}

func packagesWouldChange(host pluginapi.Host, pk *Spec) bool {
	for _, name := range pk.Install {
		if !packageInstalled(host, name) {
			return true
		}
	}
	for _, name := range pk.Purge {
		if packageInstalled(host, name) {
			return true
		}
	}
	return false
}

func needsWouldChange(pk *Spec) bool {
	return pk.Update == "once" || pk.Upgrade == "once" || pk.Autoremove == "once"
}

func packageInstalled(host pluginapi.Host, name string) bool {
	if host == nil {
		return false
	}
	cmd := "dpkg -s " + shellQuote(name) + " >/dev/null 2>&1"
	return host.RunRoot(cmd) == nil
}

func aptUpgradePreview(host pluginapi.Host) ([]string, error) {
	if host == nil {
		return nil, nil
	}
	out, err := host.RunRootWithOutput("DEBIAN_FRONTEND=noninteractive apt-get -s upgrade")
	if err != nil {
		return nil, err
	}
	var pkgs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs, nil
}

func aptInstallPreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	if host == nil || len(pkgs) == 0 {
		return nil, nil
	}
	quotedPkgs := make([]string, len(pkgs))
	for i, p := range pkgs {
		quotedPkgs[i] = shellQuote(p)
	}
	out, err := host.RunRootWithOutput("DEBIAN_FRONTEND=noninteractive apt-get -s install " + strings.Join(quotedPkgs, " "))
	if err != nil {
		return nil, err
	}
	var result []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result, nil
}

func aptAutoremovePreview(host pluginapi.Host) ([]string, error) {
	if host == nil {
		return nil, nil
	}
	out, err := host.RunRootWithOutput("DEBIAN_FRONTEND=noninteractive apt-get -s autoremove")
	if err != nil {
		return nil, err
	}
	var pkgs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Remv ") && !strings.HasPrefix(line, "Remv\t") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs, nil
}

var checkAptLock = defaultCheckAptLock

func defaultCheckAptLock(host pluginapi.Host) error {
	out, err := host.RunRootWithOutput("fuser /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/lib/dpkg/lock-frontend 2>/dev/null || true")
	if err != nil {
		return nil
	}
	if strings.TrimSpace(out) != "" {
		return fmt.Errorf("apt/dpkg lock is held by another process (PIDs: %s); wait for it to finish or investigate with: sudo lsof /var/lib/dpkg/lock", strings.TrimSpace(out))
	}
	return nil
}

func Apply(ctx pluginapi.Context, pk *Spec) error {
	logger.Debugf(
		"handlePackages: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove,
	)
	if err := validatePackageNames(pk.Install); err != nil {
		return fmt.Errorf("packages step: %w", err)
	}
	if err := validatePackageNames(pk.Purge); err != nil {
		return fmt.Errorf("packages step: %w", err)
	}
	if ctx.Host == nil {
		return fmt.Errorf("packages step: host context is required")
	}

	if err := checkAptLock(ctx.Host); err != nil {
		return fmt.Errorf("packages step: %w", err)
	}

	wouldChange := false
	if needsWouldChange(pk) {
		wouldChange = packagesWouldChange(ctx.Host, pk)
	}

	runUpdate, err := shouldRun(ctx.Host, pk.Update, stateLastUpdate, wouldChange)
	if err != nil {
		return fmt.Errorf("packages step: invalid update mode: %w", err)
	}
	if runUpdate {
		if err := aptRunRoot(ctx.Host, fmt.Sprintf("timeout %d apt-get update -y", aptTimeoutSeconds)); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}
		if strings.HasPrefix(pk.Update, "if_") {
			markRan(ctx.Host, stateLastUpdate)
		}
	}

	runUpgrade, err := shouldRun(ctx.Host, pk.Upgrade, stateLastUpgrade, wouldChange)
	if err != nil {
		return fmt.Errorf("packages step: invalid upgrade mode: %w", err)
	}
	if runUpgrade {
		if err := aptRunRoot(ctx.Host, fmt.Sprintf("timeout %d apt-get upgrade -y", aptTimeoutSeconds)); err != nil {
			return fmt.Errorf("apt-get upgrade failed: %w", err)
		}
		if strings.HasPrefix(pk.Upgrade, "if_") {
			markRan(ctx.Host, stateLastUpgrade)
		}
	}

	if len(pk.Install) > 0 {
		quoted := make([]string, len(pk.Install))
		for i, p := range pk.Install {
			quoted[i] = shellQuote(p)
		}
		cmd := fmt.Sprintf("timeout %d apt-get install -y ", aptTimeoutSeconds) + strings.Join(quoted, " ")
		if err := aptRunRoot(ctx.Host, cmd); err != nil {
			return fmt.Errorf("apt-get install failed (%s): %w", strings.Join(pk.Install, ","), err)
		}
	}

	if len(pk.Purge) > 0 {
		quoted := make([]string, len(pk.Purge))
		for i, p := range pk.Purge {
			quoted[i] = shellQuote(p)
		}
		cmd := fmt.Sprintf("timeout %d apt-get purge -y ", aptTimeoutSeconds) + strings.Join(quoted, " ")
		if err := aptRunRoot(ctx.Host, cmd); err != nil {
			return fmt.Errorf("apt-get purge failed (%s): %w", strings.Join(pk.Purge, ","), err)
		}
	}

	runAutoremove, err := shouldRun(ctx.Host, pk.Autoremove, stateLastAutoremove, wouldChange)
	if err != nil {
		return fmt.Errorf("packages step: invalid autoremove mode: %w", err)
	}
	if runAutoremove {
		if err := aptRunRoot(ctx.Host, fmt.Sprintf("timeout %d apt-get autoremove -y", aptTimeoutSeconds)); err != nil {
			return fmt.Errorf("apt-get autoremove failed: %w", err)
		}
		if strings.HasPrefix(pk.Autoremove, "if_") {
			markRan(ctx.Host, stateLastAutoremove)
		}
	}

	return nil
}

type opDecision struct {
	willRun bool
	reason  string
}

func planOpDecision(host pluginapi.Host, mode, stateFile string, wouldChange bool) (opDecision, error) {
	switch mode {
	case "", "never":
		return opDecision{false, ""}, nil
	case "always":
		return opDecision{true, "always"}, nil
	case "once":
		if wouldChange {
			return opDecision{true, "once: packages need to change"}, nil
		}
		return opDecision{false, "once: packages already aligned"}, nil
	default:
		dur, err := parseSinceDuration(mode)
		if err != nil {
			return opDecision{}, err
		}
		info, statErr := host.Stat(stateFile)
		if statErr != nil {
			return opDecision{true, "never ran"}, nil
		}
		elapsed := time.Since(info.ModTime())
		if elapsed >= dur {
			return opDecision{true, fmt.Sprintf("last ran %s ago, threshold %s", formatElapsed(elapsed), mode)}, nil
		}
		remaining := dur - elapsed
		return opDecision{false, fmt.Sprintf("ran %s ago, threshold %s (next run in ~%s)", formatElapsed(elapsed), mode, formatElapsed(remaining))}, nil
	}
}

func formatElapsed(d time.Duration) string {
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

func Plan(ctx pluginapi.Context, pk *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planPackages: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove)
	if err := validatePackageNames(pk.Install); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: %w", err)
	}
	if err := validatePackageNames(pk.Purge); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: %w", err)
	}
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: host context is required")
	}

	var details []string
	var diff []string
	var highlights []string

	type pkgInfo struct {
		name      string
		installed bool
	}
	installInfos := make([]pkgInfo, len(pk.Install))
	var installWillChange []string
	for i, name := range pk.Install {
		installed := packageInstalled(ctx.Host, name)
		installInfos[i] = pkgInfo{name, installed}
		if !installed {
			installWillChange = append(installWillChange, name)
		}
	}
	purgeInfos := make([]pkgInfo, len(pk.Purge))
	var purgeWillChange []string
	for i, name := range pk.Purge {
		installed := packageInstalled(ctx.Host, name)
		purgeInfos[i] = pkgInfo{name, installed}
		if installed {
			purgeWillChange = append(purgeWillChange, name)
		}
	}
	wouldChange := len(installWillChange) > 0 || len(purgeWillChange) > 0

	updateDec, err := planOpDecision(ctx.Host, pk.Update, stateLastUpdate, wouldChange)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: invalid update mode: %w", err)
	}
	upgradeDec, err := planOpDecision(ctx.Host, pk.Upgrade, stateLastUpgrade, wouldChange)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: invalid upgrade mode: %w", err)
	}
	autoremoveDec, err := planOpDecision(ctx.Host, pk.Autoremove, stateLastAutoremove, wouldChange)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: invalid autoremove mode: %w", err)
	}

	var upgradeWillChange []string
	var installDepsWillChange []string
	var autoremoveWillChange []string

	if pk.Update != "" && pk.Update != "never" {
		if updateDec.willRun {
			details = append(details, logger.ColorGreen+"will run: apt-get update -y ("+updateDec.reason+")"+logger.ColorReset)
		} else {
			details = append(details, logger.ColorDim+"update: skipped ("+updateDec.reason+")"+logger.ColorReset)
		}
	}

	if pk.Upgrade != "" && pk.Upgrade != "never" {
		if upgradeDec.willRun {
			up, err := aptUpgradePreview(ctx.Host)
			if err != nil {
				highlights = append(highlights, fmt.Sprintf("cannot preview package upgrades (%v)", err))
				details = append(details,
					logger.ColorRed+fmt.Sprintf("upgrade: failed to preview upgrades (%v)", err)+logger.ColorReset,
				)
			} else if len(up) == 0 {
				details = append(details,
					logger.ColorBlue+"upgrade: no packages would be upgraded (no-op) ("+upgradeDec.reason+")"+logger.ColorReset,
				)
			} else {
				upgradeWillChange = up
				details = append(details,
					logger.ColorGreen+fmt.Sprintf("upgrade: would upgrade %d package(s): %s (%s)",
						len(up), strings.Join(up, ", "), upgradeDec.reason)+logger.ColorReset,
				)
			}
		} else {
			details = append(details, logger.ColorDim+"upgrade: skipped ("+upgradeDec.reason+")"+logger.ColorReset)
		}
	}

	for _, info := range installInfos {
		if info.installed {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (no install change)%s",
				logger.ColorBlue, info.name, logger.ColorReset,
				logger.ColorYellow, logger.ColorReset,
			))
		} else {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %snot installed (will be installed)%s",
				logger.ColorBlue, info.name, logger.ColorReset,
				logger.ColorGreen, logger.ColorReset,
			))
		}
	}
	if len(pk.Install) > 0 {
		all, err := aptInstallPreview(ctx.Host, pk.Install)
		if err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview dependency installs (%v)", err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("install: failed to preview dependency installs (%v)", err)+logger.ColorReset,
			)
		} else {
			explicit := make(map[string]struct{}, len(pk.Install))
			for _, name := range pk.Install {
				explicit[name] = struct{}{}
			}
			for _, name := range all {
				if _, ok := explicit[name]; ok {
					continue
				}
				installDepsWillChange = append(installDepsWillChange, name)
			}
			if len(installDepsWillChange) > 0 {
				details = append(details,
					logger.ColorDim+fmt.Sprintf("apt will also install %d dependency package(s): %s",
						len(installDepsWillChange), strings.Join(installDepsWillChange, ", "))+logger.ColorReset,
				)
			}
		}
	}

	for _, info := range purgeInfos {
		if info.installed {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (will be purged)%s",
				logger.ColorBlue, info.name, logger.ColorReset,
				logger.ColorRed, logger.ColorReset,
			))
		} else {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %snot installed (purge has no effect)%s",
				logger.ColorBlue, info.name, logger.ColorReset,
				logger.ColorDim, logger.ColorReset,
			))
		}
	}

	if pk.Autoremove != "" && pk.Autoremove != "never" {
		if autoremoveDec.willRun {
			pkgs, err := aptAutoremovePreview(ctx.Host)
			if err != nil {
				highlights = append(highlights, fmt.Sprintf("cannot preview autoremove packages (%v)", err))
				details = append(details,
					logger.ColorRed+fmt.Sprintf("autoremove: failed to preview packages to be removed (%v)", err)+logger.ColorReset,
				)
			} else if len(pkgs) == 0 {
				msg := "autoremove: no packages would be removed (no-op)"
				if upgradeDec.willRun {
					msg = "autoremove: no packages would be removed (current state; may change after upgrade)"
				}
				details = append(details, logger.ColorBlue+msg+" ("+autoremoveDec.reason+")"+logger.ColorReset)
			} else {
				autoremoveWillChange = pkgs
				msg := fmt.Sprintf("autoremove: would remove %d package(s): %s", len(pkgs), strings.Join(pkgs, ", "))
				if upgradeDec.willRun {
					msg += " (may change after upgrade)"
				}
				details = append(details, logger.ColorGreen+msg+" ("+autoremoveDec.reason+")"+logger.ColorReset)
			}
		} else {
			details = append(details, logger.ColorDim+"autoremove: skipped ("+autoremoveDec.reason+")"+logger.ColorReset)
		}
	}

	noUpdate := !updateDec.willRun
	noUpgrade := !upgradeDec.willRun || len(upgradeWillChange) == 0
	noInstall := len(installWillChange) == 0 && len(installDepsWillChange) == 0
	noPurge := len(purgeWillChange) == 0
	noAutoremove := !autoremoveDec.willRun || len(autoremoveWillChange) == 0

	var noop int = 2
	if noUpdate && noUpgrade && noInstall && noPurge && noAutoremove {
		noop = 0
	} else if updateDec.willRun && noUpgrade && noInstall && noPurge && noAutoremove {
		noop = 1
	}

	if updateDec.willRun {
		diff = append(diff, "package index metadata: current -> refreshed from configured repositories")
	}
	for _, name := range upgradeWillChange {
		diff = append(diff, fmt.Sprintf("package %q: installed -> upgraded", name))
	}
	for _, name := range installWillChange {
		diff = append(diff, fmt.Sprintf("package %q: absent -> installed", name))
	}
	for _, name := range installDepsWillChange {
		diff = append(diff, fmt.Sprintf("package %q: absent -> installed (dependency)", name))
	}
	for _, name := range purgeWillChange {
		diff = append(diff, fmt.Sprintf("package %q: installed -> purged", name))
	}
	for _, name := range autoremoveWillChange {
		diff = append(diff, fmt.Sprintf("package %q: installed -> removed by autoremove", name))
	}

	var summary string
	var operatorSummary string
	if noop == 0 {
		summary = "packages step: no-op (no update/upgrade/install/purge/autoremove specified or no changes required)"
		operatorSummary = "Package state already matches the requested policy"
	} else if noop == 1 {
		summary = "packages step: update package index (install/upgrade/purge/autoremove currently no-op; may change after update)"
		operatorSummary = "Refresh package metadata; install, upgrade, purge, and autoremove decisions may change after the update"
	} else {
		var summaryParts []string
		if updateDec.willRun {
			summaryParts = append(summaryParts, "update package index")
		}
		if upgradeDec.willRun {
			if len(upgradeWillChange) == 0 {
				if updateDec.willRun {
					summaryParts = append(summaryParts,
						fmt.Sprintf("upgrade installed packages %s(none currently; may change after update)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts, fmt.Sprintf("upgrade installed packages %s(none)%s", logger.ColorGreen, logger.ColorReset))
				}
			} else {
				summaryParts = append(summaryParts, "upgrade: "+strings.Join(upgradeWillChange, ", "))
			}
		}
		if len(installWillChange) > 0 {
			summaryParts = append(summaryParts, "install: "+strings.Join(installWillChange, ", "))
		}
		if len(installDepsWillChange) > 0 {
			summaryParts = append(summaryParts, "install dependencies: "+strings.Join(installDepsWillChange, ", "))
		}
		if len(purgeWillChange) > 0 {
			summaryParts = append(summaryParts, "purge: "+strings.Join(purgeWillChange, ", "))
		}
		if autoremoveDec.willRun {
			if len(autoremoveWillChange) == 0 {
				if upgradeDec.willRun {
					summaryParts = append(summaryParts,
						fmt.Sprintf("autoremove %s(none currently; may change after upgrade)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts, "autoremove unused packages (no packages to remove)")
				}
			} else {
				line := "autoremove unused packages: " + strings.Join(autoremoveWillChange, ", ")
				if upgradeDec.willRun {
					line += " (may change after upgrade)"
				}
				summaryParts = append(summaryParts, line)
			}
		}
		summary = "packages step: " + strings.Join(summaryParts, "; ")
		operatorSummary = packagesSentence(summaryParts)
	}

	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		WillChange:      noop != 0,
		OperatorSummary: operatorSummary,
		Highlights:      highlights,
	}, nil
}

func Capture(ctx pluginapi.Context, stepID string, pk *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if pk == nil {
		return record, fmt.Errorf("step %q (type=packages): packages spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("packages step: host context is required")
	}

	pkgs, err := snapshotPackageState(ctx.Host, pk)
	if err != nil {
		return record, err
	}

	record.RollbackMode = pluginapi.ModeBestEffort
	record.Objects = pkgs
	if pk.Update != "" && pk.Update != "never" {
		record.Notes = append(record.Notes, "apt update is not directly reversible")
	}
	if pk.Upgrade != "" && pk.Upgrade != "never" {
		record.Notes = append(record.Notes, "apt upgrade rollback is best-effort")
	}
	if pk.Autoremove != "" && pk.Autoremove != "never" {
		record.Notes = append(record.Notes, "apt autoremove rollback is best-effort")
	}
	return record, nil
}

func snapshotPackageState(host pluginapi.Host, pk *Spec) ([]pluginapi.ObjectRecord, error) {
	pkgSet := map[string]struct{}{}
	installSet := map[string]struct{}{}
	purgeSet := map[string]struct{}{}

	for _, name := range pk.Install {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		pkgSet[n] = struct{}{}
		installSet[n] = struct{}{}
	}
	for _, name := range pk.Purge {
		n := strings.TrimSpace(name)
		if n == "" {
			continue
		}
		pkgSet[n] = struct{}{}
		purgeSet[n] = struct{}{}
	}

	names := make([]string, 0, len(pkgSet))
	for name := range pkgSet {
		names = append(names, name)
	}
	sort.Strings(names)

	records := make([]pluginapi.ObjectRecord, 0, len(names))
	for _, name := range names {
		cmd := "dpkg-query -W -f='${Status}\\t${Version}' " + shellQuote(name) + " 2>/dev/null || true"
		out, err := host.RunRootWithOutput(cmd)
		if err != nil {
			return nil, fmt.Errorf("capture package state for %q: %w", name, err)
		}

		raw := strings.TrimSpace(out)
		state := pluginapi.PackageState{
			Name:             name,
			RequestedInstall: inSet(installSet, name),
			RequestedPurge:   inSet(purgeSet, name),
		}

		if strings.HasPrefix(raw, "install ok installed\t") {
			state.WasInstalled = true
			state.Version = strings.TrimPrefix(raw, "install ok installed\t")
		} else if raw == "install ok installed" {
			state.WasInstalled = true
		}

		records = append(records, pluginapi.ObjectRecord{
			Kind:    pluginapi.ObjectPackage,
			Package: &state,
		})
	}
	return records, nil
}

func inSet(set map[string]struct{}, name string) bool {
	_, ok := set[name]
	return ok
}

func packagesSentence(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	text := strings.Join(parts, "; ")
	return strings.ToUpper(text[:1]) + text[1:]
}

func restorePackageBestEffort(host pluginapi.Host, p pluginapi.PackageState) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("package name is empty")
	}

	if p.RequestedInstall && !p.WasInstalled {
		if err := host.RunRoot("apt-get purge -y " + shellQuote(name)); err != nil {
			return fmt.Errorf("purge package %q: %w", name, err)
		}
	}

	if p.RequestedPurge && p.WasInstalled {
		if p.Version != "" {
			withVersion := name + "=" + p.Version
			if err := host.RunRoot("DEBIAN_FRONTEND=noninteractive apt-get install -y " + shellQuote(withVersion)); err == nil {
				return nil
			}
		}
		if err := host.RunRoot("DEBIAN_FRONTEND=noninteractive apt-get install -y " + shellQuote(name)); err != nil {
			return fmt.Errorf("reinstall package %q: %w", name, err)
		}
	}

	return nil
}

func packageStateConflict(host pluginapi.Host, p pluginapi.PackageState) []string {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil
	}
	var conflicts []string
	currentInstalled := packageInstalled(host, name)
	if currentInstalled != p.WasInstalled {
		conflicts = append(conflicts, fmt.Sprintf("package %q: installed=%v but journal recorded installed=%v after apply (changed since apply)", name, currentInstalled, p.WasInstalled))
	} else if currentInstalled && p.WasInstalled && p.Version != "" {
		currentVersion := queryPackageVersion(host, name)
		if currentVersion != "" && currentVersion != p.Version {
			conflicts = append(conflicts, fmt.Sprintf("package %q: version is %q but journal recorded %q after apply (upgraded since apply)", name, currentVersion, p.Version))
		}
	}
	return conflicts
}

func queryPackageVersion(host pluginapi.Host, name string) string {
	out, err := host.RunRootWithOutput("dpkg-query -W -f='${Version}' " + shellQuote(name) + " 2>/dev/null")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
