package packages

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

// PkgInfo is one requested package and whether the host currently has it.
type PkgInfo struct {
	Name      string
	Installed bool
}

// Preview is what a backend's preview command produced. A failure is carried
// rather than returned: a package manager that cannot preview is a warning on
// the plan, not a reason to abandon it.
type Preview struct {
	Packages []string
	Err      error
}

// PlanInputs is everything RenderPlan needs, already computed by the caller.
// It carries results only: no commands, no functions, nothing that would let
// the rendering dispatch back into a backend.
type PlanInputs struct {
	UpdateMode     string
	UpgradeMode    string
	AutoremoveMode string

	InstallInfos []PkgInfo
	PurgeInfos   []PkgInfo

	Update     Decision
	Upgrade    Decision
	Autoremove Decision

	// UpgradePreview and AutoremovePreview are only consulted when the matching
	// decision says the operation will run; InstallPreview and PurgePreview only
	// when there are packages to install or purge.
	UpgradePreview    Preview
	InstallPreview    Preview
	PurgePreview      Preview
	AutoremovePreview Preview

	// PurgeAlsoRemoves is the collateral removal set the step declares it
	// accepts. Anything the purge transaction removes that is named neither here
	// nor in purge is what apply refuses on.
	PurgeAlsoRemoves []string
}

// WouldChange reports whether install or purge alone would change the host,
// which is what the "once" op mode keys off.
func WouldChange(installInfos, purgeInfos []PkgInfo) bool {
	for _, info := range installInfos {
		if !info.Installed {
			return true
		}
	}
	for _, info := range purgeInfos {
		if info.Installed {
			return true
		}
	}
	return false
}

// RenderPlan turns the computed state into the plan every package plugin
// prints. It lives here so the report reads identically whichever package
// manager produced it.
func RenderPlan(in PlanInputs) pluginapi.PlanResult {
	var details []string
	var diff []string
	var highlights []string

	var installWillChange []string
	for _, info := range in.InstallInfos {
		if !info.Installed {
			installWillChange = append(installWillChange, info.Name)
		}
	}
	var purgeWillChange []string
	for _, info := range in.PurgeInfos {
		if info.Installed {
			purgeWillChange = append(purgeWillChange, info.Name)
		}
	}

	var upgradeWillChange []string
	var installDepsWillChange []string
	var purgeDepsWillChange []string
	var autoremoveWillChange []string

	if in.UpdateMode != "" && in.UpdateMode != "never" {
		if in.Update.WillRun {
			details = append(details, logger.ColorGreen+"will run: package index update ("+in.Update.Reason+")"+logger.ColorReset)
		} else {
			details = append(details, logger.ColorDim+"update: skipped ("+in.Update.Reason+")"+logger.ColorReset)
		}
	}

	if in.UpgradeMode != "" && in.UpgradeMode != "never" {
		if in.Upgrade.WillRun {
			switch {
			case in.UpgradePreview.Err != nil:
				highlights = append(highlights, fmt.Sprintf("cannot preview package upgrades (%v)", in.UpgradePreview.Err))
				details = append(details,
					logger.ColorRed+fmt.Sprintf("upgrade: failed to preview upgrades (%v)", in.UpgradePreview.Err)+logger.ColorReset,
				)
			case len(in.UpgradePreview.Packages) == 0:
				details = append(details,
					logger.ColorBlue+"upgrade: no packages would be upgraded (no-op) ("+in.Upgrade.Reason+")"+logger.ColorReset,
				)
			default:
				upgradeWillChange = in.UpgradePreview.Packages
				details = append(details,
					logger.ColorGreen+fmt.Sprintf("upgrade: would upgrade %d package(s) (%s)",
						len(upgradeWillChange), in.Upgrade.Reason)+logger.ColorReset,
				)
			}
		} else {
			details = append(details, logger.ColorDim+"upgrade: skipped ("+in.Upgrade.Reason+")"+logger.ColorReset)
		}
	}

	for _, info := range in.InstallInfos {
		if info.Installed {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (no install change)%s",
				logger.ColorBlue, info.Name, logger.ColorReset,
				logger.ColorYellow, logger.ColorReset,
			))
		} else {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %snot installed (will be installed)%s",
				logger.ColorBlue, info.Name, logger.ColorReset,
				logger.ColorGreen, logger.ColorReset,
			))
		}
	}
	if len(in.InstallInfos) > 0 {
		if in.InstallPreview.Err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview dependency installs (%v)", in.InstallPreview.Err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("install: failed to preview dependency installs (%v)", in.InstallPreview.Err)+logger.ColorReset,
			)
		} else {
			explicit := make(map[string]struct{}, len(in.InstallInfos))
			for _, info := range in.InstallInfos {
				explicit[info.Name] = struct{}{}
			}
			for _, name := range in.InstallPreview.Packages {
				if _, ok := explicit[name]; ok {
					continue
				}
				installDepsWillChange = append(installDepsWillChange, name)
			}
			if len(installDepsWillChange) > 0 {
				details = append(details,
					logger.ColorDim+fmt.Sprintf("the package manager will also install %d dependency package(s)",
						len(installDepsWillChange))+logger.ColorReset,
				)
			}
		}
	}

	for _, info := range in.PurgeInfos {
		if info.Installed {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %scurrently installed (will be purged)%s",
				logger.ColorBlue, info.Name, logger.ColorReset,
				logger.ColorRed, logger.ColorReset,
			))
		} else {
			details = append(details, fmt.Sprintf(
				"%spackage %q:%s %snot installed (purge has no effect)%s",
				logger.ColorBlue, info.Name, logger.ColorReset,
				logger.ColorDim, logger.ColorReset,
			))
		}
	}

	if len(in.PurgeInfos) > 0 {
		if in.PurgePreview.Err != nil {
			highlights = append(highlights, fmt.Sprintf("cannot preview the purge transaction (%v)", in.PurgePreview.Err))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("purge: failed to preview the removal transaction (%v)", in.PurgePreview.Err)+logger.ColorReset,
			)
		} else {
			explicit := make(map[string]struct{}, len(in.PurgeInfos))
			for _, info := range in.PurgeInfos {
				explicit[info.Name] = struct{}{}
			}
			for _, name := range in.PurgePreview.Packages {
				if _, ok := explicit[name]; ok {
					continue
				}
				purgeDepsWillChange = append(purgeDepsWillChange, name)
			}
			if len(purgeDepsWillChange) > 0 {
				details = append(details,
					logger.ColorRed+fmt.Sprintf("purge: the package manager will also remove %d other package(s): %s",
						len(purgeDepsWillChange), strings.Join(purgeDepsWillChange, ", "))+logger.ColorReset,
				)
			}
			var want []string
			for _, info := range in.PurgeInfos {
				want = append(want, info.Name)
			}
			want = append(want, in.PurgeAlsoRemoves...)
			if extra := UnexpectedRemovals(want, in.PurgePreview.Packages); len(extra) > 0 {
				msg := fmt.Sprintf(
					"purge would also remove %s, which the step does not declare; apply will refuse until they are listed in purge_also_removes",
					strings.Join(extra, ", "))
				highlights = append(highlights, msg)
				details = append(details, logger.ColorRed+"purge: "+msg+logger.ColorReset)
			}
		}
	}

	if in.AutoremoveMode != "" && in.AutoremoveMode != "never" {
		if in.Autoremove.WillRun {
			switch {
			case in.AutoremovePreview.Err != nil:
				highlights = append(highlights, fmt.Sprintf("cannot preview autoremove packages (%v)", in.AutoremovePreview.Err))
				details = append(details,
					logger.ColorRed+fmt.Sprintf("autoremove: failed to preview packages to be removed (%v)", in.AutoremovePreview.Err)+logger.ColorReset,
				)
			case len(in.AutoremovePreview.Packages) == 0:
				msg := "autoremove: no packages would be removed (no-op)"
				if in.Upgrade.WillRun {
					msg = "autoremove: no packages would be removed (current state; may change after upgrade)"
				}
				details = append(details, logger.ColorBlue+msg+" ("+in.Autoremove.Reason+")"+logger.ColorReset)
			default:
				autoremoveWillChange = in.AutoremovePreview.Packages
				msg := fmt.Sprintf("autoremove: would remove %d package(s)", len(autoremoveWillChange))
				if in.Upgrade.WillRun {
					msg += " (may change after upgrade)"
				}
				details = append(details, logger.ColorGreen+msg+" ("+in.Autoremove.Reason+")"+logger.ColorReset)
			}
		} else {
			details = append(details, logger.ColorDim+"autoremove: skipped ("+in.Autoremove.Reason+")"+logger.ColorReset)
		}
	}

	noUpdate := !in.Update.WillRun
	noUpgrade := !in.Upgrade.WillRun || len(upgradeWillChange) == 0
	noInstall := len(installWillChange) == 0 && len(installDepsWillChange) == 0
	noPurge := len(purgeWillChange) == 0 && len(purgeDepsWillChange) == 0
	noAutoremove := !in.Autoremove.WillRun || len(autoremoveWillChange) == 0

	noop := 2
	if noUpdate && noUpgrade && noInstall && noPurge && noAutoremove {
		noop = 0
	} else if in.Update.WillRun && noUpgrade && noInstall && noPurge && noAutoremove {
		noop = 1
	}

	if in.Update.WillRun {
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
	for _, name := range purgeDepsWillChange {
		diff = append(diff, fmt.Sprintf("package %q: installed -> removed (pulled in by purge)", name))
	}
	for _, name := range autoremoveWillChange {
		diff = append(diff, fmt.Sprintf("package %q: installed -> removed by autoremove", name))
	}

	var summary string
	var operatorSummary string
	switch noop {
	case 0:
		summary = "packages step: no-op (no update/upgrade/install/purge/autoremove specified or no changes required)"
		operatorSummary = "Package state already matches the requested policy"
	case 1:
		summary = "packages step: update package index (install/upgrade/purge/autoremove currently no-op; may change after update)"
		operatorSummary = "Refresh package metadata; install, upgrade, purge, and autoremove decisions may change after the update"
	default:
		var parts []string
		if in.Update.WillRun {
			parts = append(parts, "update package index")
		}
		if in.Upgrade.WillRun {
			if len(upgradeWillChange) == 0 {
				if in.Update.WillRun {
					parts = append(parts,
						fmt.Sprintf("upgrade installed packages %s(none currently; may change after update)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					parts = append(parts, fmt.Sprintf("upgrade installed packages %s(none)%s", logger.ColorGreen, logger.ColorReset))
				}
			} else {
				parts = append(parts, fmt.Sprintf("upgrade %d package(s)", len(upgradeWillChange)))
			}
		}
		if len(installWillChange) > 0 {
			parts = append(parts, "install: "+strings.Join(installWillChange, ", "))
		}
		if len(installDepsWillChange) > 0 {
			parts = append(parts, fmt.Sprintf("install %d dependency package(s)", len(installDepsWillChange)))
		}
		if len(purgeWillChange) > 0 {
			parts = append(parts, "purge: "+strings.Join(purgeWillChange, ", "))
		}
		if len(purgeDepsWillChange) > 0 {
			parts = append(parts, fmt.Sprintf("remove %d package(s) pulled in by the purge", len(purgeDepsWillChange)))
		}
		if in.Autoremove.WillRun {
			if len(autoremoveWillChange) == 0 {
				if in.Upgrade.WillRun {
					parts = append(parts,
						fmt.Sprintf("autoremove %s(none currently; may change after upgrade)%s", logger.ColorYellow, logger.ColorReset))
				} else {
					parts = append(parts, "autoremove unused packages (no packages to remove)")
				}
			} else {
				line := fmt.Sprintf("autoremove %d unused package(s)", len(autoremoveWillChange))
				if in.Upgrade.WillRun {
					line += " (may change after upgrade)"
				}
				parts = append(parts, line)
			}
		}
		summary = "packages step: " + strings.Join(parts, "; ")
		operatorSummary = packagesSentence(parts)
	}

	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		WillChange:      noop != 0,
		OperatorSummary: operatorSummary,
		Highlights:      highlights,
	}
}

func packagesSentence(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	text := strings.Join(parts, "; ")
	return strings.ToUpper(text[:1]) + text[1:]
}
