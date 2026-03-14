package packages

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

func packageInstalled(host pluginapi.Host, name string) bool {
	if host == nil {
		return false
	}
	cmd := fmt.Sprintf("dpkg -s %q >/dev/null 2>&1", name)
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
	out, err := host.RunRootWithOutput("DEBIAN_FRONTEND=noninteractive apt-get -s install " + strings.Join(pkgs, " "))
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

func Apply(ctx pluginapi.ApplyContext, pk *Spec) error {
	logger.Debugf(
		"handlePackages: update=%v upgrade=%v install=%v purge=%v autoremove=%v\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove,
	)
	if ctx.Host == nil {
		return fmt.Errorf("packages step: host context is required")
	}

	if pk.Update {
		if err := ctx.Host.RunRoot("apt-get update -y"); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}
	}

	if pk.Upgrade {
		if err := ctx.Host.RunRoot("apt-get upgrade -y"); err != nil {
			return fmt.Errorf("apt-get upgrade failed: %w", err)
		}
	}

	if len(pk.Install) > 0 {
		cmd := "apt-get install -y " + strings.Join(pk.Install, " ")
		if err := ctx.Host.RunRoot(cmd); err != nil {
			return fmt.Errorf("apt-get install failed (%s): %w", strings.Join(pk.Install, ","), err)
		}
	}

	if len(pk.Purge) > 0 {
		cmd := "apt-get purge -y " + strings.Join(pk.Purge, " ")
		if err := ctx.Host.RunRoot(cmd); err != nil {
			return fmt.Errorf("apt-get purge failed (%s): %w", strings.Join(pk.Purge, ","), err)
		}
	}

	if pk.Autoremove {
		if err := ctx.Host.RunRoot("apt-get autoremove -y"); err != nil {
			return fmt.Errorf("apt-get autoremove failed: %w", err)
		}
	}

	return nil
}

func Plan(ctx pluginapi.PlanContext, pk *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planPackages: update=%v upgrade=%v install=%v purge=%v autoremove=%v\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove)
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("packages step: host context is required")
	}

	var details []string
	var diff []string
	var highlights []string

	var installWillChange []string
	var installDepsWillChange []string
	var purgeWillChange []string
	var upgradeWillChange []string
	var autoremoveWillChange []string

	if pk.Update {
		details = append(details, logger.ColorGreen+"will run: apt-get update -y"+logger.ColorReset)
		diff = append(diff, "package index metadata: current -> refreshed from configured repositories")
	}
	if pk.Upgrade {
		up, err := aptUpgradePreview(ctx.Host)
		if err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview package upgrades (%v)", err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("upgrade: failed to preview upgrades (%v)", err)+logger.ColorReset,
			)
		} else if len(up) == 0 {
			details = append(details,
				logger.ColorBlue+"upgrade: no packages would be upgraded (no-op)"+logger.ColorReset,
			)
		} else {
			upgradeWillChange = up
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("upgrade: would upgrade %d package(s): %s",
					len(up), strings.Join(up, ", "))+logger.ColorReset,
			)
		}
	}

	for _, name := range pk.Install {
		if packageInstalled(ctx.Host, name) {
			line := fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (no install change)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorYellow, logger.ColorReset,
			)
			details = append(details, line)
		} else {
			installWillChange = append(installWillChange, name)

			line := fmt.Sprintf(
				"%spackage %q:%s %snot installed (will be installed)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorGreen, logger.ColorReset,
			)
			details = append(details, line)
		}
	}

	if len(pk.Install) > 0 {
		all, err := aptInstallPreview(ctx.Host, pk.Install)
		if err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview dependency installs (%v)", err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("install: failed to preview dependency installs (%v)", err)+logger.ColorReset,
			)
		} else if len(all) > 0 {
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

	for _, name := range pk.Purge {
		if packageInstalled(ctx.Host, name) {
			purgeWillChange = append(purgeWillChange, name)

			line := fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (will be purged)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorRed, logger.ColorReset,
			)
			details = append(details, line)
		} else {
			line := fmt.Sprintf(
				"%spackage %q:%s %snot installed (purge has no effect)%s",
				logger.ColorBlue, name, logger.ColorReset,
				logger.ColorDim, logger.ColorReset,
			)
			details = append(details, line)
		}
	}

	if pk.Autoremove {
		pkgs, err := aptAutoremovePreview(ctx.Host)
		if err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview autoremove packages (%v)", err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("autoremove: failed to preview packages to be removed (%v)", err)+logger.ColorReset,
			)
		} else if len(pkgs) == 0 {
			msg := "autoremove: no packages would be removed (no-op)"
			if pk.Upgrade {
				msg = "autoremove: no packages would be removed (current state; may change after upgrade)"
			}
			details = append(details, logger.ColorBlue+msg+logger.ColorReset)
		} else {
			autoremoveWillChange = pkgs
			msg := fmt.Sprintf("autoremove: would remove %d package(s): %s", len(pkgs), strings.Join(pkgs, ", "))
			if pk.Upgrade {
				msg += " (may change after upgrade)"
			}
			details = append(details, logger.ColorGreen+msg+logger.ColorReset)
		}
	}

	var summary string
	var operatorSummary string
	var noop int = 2
	if !pk.Update &&
		(!pk.Upgrade || len(upgradeWillChange) == 0) &&
		len(installWillChange) == 0 &&
		len(installDepsWillChange) == 0 &&
		len(purgeWillChange) == 0 &&
		(!pk.Autoremove || len(autoremoveWillChange) == 0) {
		noop = 0
		summary = "packages step: no-op (no update/upgrade/install/purge/autoremove specified or no changes required)"
		operatorSummary = "Package state already matches the requested policy"
	} else if pk.Update &&
		len(upgradeWillChange) == 0 &&
		len(installWillChange) == 0 &&
		len(installDepsWillChange) == 0 &&
		len(purgeWillChange) == 0 &&
		(!pk.Autoremove || len(autoremoveWillChange) == 0) {
		summary = "packages step: update package index (install/upgrade/purge/autoremove currently no-op; may change after update)"
		noop = 1
		operatorSummary = "Refresh package metadata; install, upgrade, purge, and autoremove decisions may change after the update"
	} else {
		var summaryParts []string
		if pk.Update {
			summaryParts = append(summaryParts, "update package index")
		}
		if pk.Upgrade {
			if len(upgradeWillChange) == 0 {
				if pk.Update {
					summaryParts = append(summaryParts,
						fmt.Sprintf("upgrade installed packages %s(none currently; may change after update)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts, fmt.Sprintf("upgrade installed packages %s(none)%s", logger.ColorGreen, logger.ColorReset))
				}
			} else {
				summaryParts = append(summaryParts,
					"upgrade: "+strings.Join(upgradeWillChange, ", "))
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
		if pk.Autoremove {
			if len(autoremoveWillChange) == 0 {
				if pk.Upgrade {
					summaryParts = append(summaryParts,
						fmt.Sprintf("autoremove %s(none currently; may change after upgrade)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					summaryParts = append(summaryParts,
						"autoremove unused packages (no packages to remove)")
				}
			} else {
				line := "autoremove unused packages: " + strings.Join(autoremoveWillChange, ", ")
				if pk.Upgrade {
					line += " (may change after upgrade)"
				}
				summaryParts = append(summaryParts, line)
			}
		}
		summary = "packages step: " + strings.Join(summaryParts, "; ")
		operatorSummary = packagesSentence(summaryParts)
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

	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		Noop:            noop,
		OperatorSummary: operatorSummary,
		Highlights:      highlights,
	}, nil
}

func Capture(ctx pluginapi.CaptureContext, stepID string, pk *Spec) (pluginapi.StepRecord, error) {
	record := pluginapi.StepRecord{
		ID:   stepID,
		Type: "packages",
	}
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
	if pk.Update {
		record.Notes = append(record.Notes, "apt update is not directly reversible")
	}
	if pk.Upgrade {
		record.Notes = append(record.Notes, "apt upgrade rollback is best-effort")
	}
	if pk.Autoremove {
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
		cmd := "dpkg-query -W -f='${Status}\\t${Version}' " + strconv.Quote(name) + " 2>/dev/null || true"
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
