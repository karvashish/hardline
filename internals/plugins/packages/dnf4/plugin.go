// Package dnf4 is the packages_dnf4 plugin: package management through dnf-3,
// as shipped on RHEL 9, Rocky 9 and Alma 9. It is a separate plugin from dnf5
// rather than a version probe, because the two print different transaction
// tables and dnf5 renamed check-update to check-upgrade.
package dnf4

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

const pluginName = "packages_dnf4"

// Spec is this plugin's step config. PurgeAlsoRemoves is the profile's explicit
// acknowledgement of collateral: dnf resolves a removal outwards, and every
// extra package the transaction takes has to be named here before apply will
// run it.
type Spec struct {
	Update           string   `json:"update,omitempty"`
	Upgrade          string   `json:"upgrade,omitempty"`
	Autoremove       string   `json:"autoremove,omitempty"`
	Install          []string `json:"install"`
	Purge            []string `json:"purge"`
	PurgeAlsoRemoves []string `json:"purge_also_removes,omitempty"`
}

var (
	nameRe = packages.RPMNameRe
	pinRe  = packages.RPMPinRe
)

const lockHint = "investigate with: sudo lsof /var/lib/rpm/.rpm.lock"

var lockCheck = packages.LockProbe(
	"/var/lib/rpm/.rpm.lock",
	"/var/cache/dnf/metadata_lock.pid",
)

var (
	updateCmd     = packages.TimeoutCmd("dnf -q -y makecache --refresh")
	upgradeCmd    = packages.TimeoutCmd("dnf -y upgrade")
	installCmd    = packages.TimeoutCmd("dnf -y install")
	purgeCmd      = packages.TimeoutCmd("dnf -y remove")
	autoremoveCmd = packages.TimeoutCmd("dnf -y autoremove")

	// The rollback removal is the purge with dnf's dependency cleanup off, so
	// that it matches the transaction restore previews and refuses.
	rollbackRemoveCmd = packages.TimeoutCmd("dnf -y " + removeOpts + "remove")
)

// checkLock is a var so tests can inject a held lock.
var checkLock = func(host pluginapi.Host) error {
	return packages.CheckLock(host, lockCheck, lockHint)
}

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               pluginName,
		InternalValidation: true,
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decode(step)
			if err != nil {
				return err
			}
			return apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decode(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decode(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			return capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectPackage:
				if obj.Package == nil {
					return fmt.Errorf("%s rollback: missing package snapshot", pluginName)
				}
				return restore(host, *obj.Package)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("%s plugin cannot roll back kind %q", pluginName, obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			if after.Kind == pluginapi.ObjectPackage && after.Package != nil {
				return conflict(host, *after.Package)
			}
			return nil
		},
	}
}

func decode(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	if spec.Update == "" && spec.Upgrade == "" && spec.Autoremove == "" &&
		len(spec.Install) == 0 && len(spec.Purge) == 0 {
		return nil, fmt.Errorf("%s config is required", pluginName)
	}
	if err := validate(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validate(spec *Spec) error {
	for _, op := range []struct{ field, val string }{
		{"update", spec.Update},
		{"upgrade", spec.Upgrade},
		{"autoremove", spec.Autoremove},
	} {
		if err := packages.ValidateOpMode(op.field, op.val); err != nil {
			return err
		}
	}
	if len(spec.PurgeAlsoRemoves) > 0 && len(spec.Purge) == 0 {
		return fmt.Errorf("%s: purge_also_removes has no effect without purge", pluginName)
	}
	if err := packages.ValidateNames(nameRe, spec.PurgeAlsoRemoves); err != nil {
		return err
	}
	return packages.ValidateLists(nameRe, spec.Install, spec.Purge)
}

// installed answers from the same query capture journals, so a probe and a
// snapshot cannot disagree about a package.
func installed(host pluginapi.Host, name string) (bool, error) {
	was, _, _, err := packages.RPMQuery(host, name)
	return was, err
}

func apply(ctx pluginapi.Context, spec *Spec) error {
	logger.Debugf("%s: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		pluginName, spec.Update, spec.Upgrade, spec.Install, spec.Purge, spec.Autoremove)
	if ctx.Host == nil {
		return fmt.Errorf("%s step: host context is required", pluginName)
	}
	if err := checkLock(ctx.Host); err != nil {
		return fmt.Errorf("%s step: %w", pluginName, err)
	}

	wouldChange := false
	if packages.NeedsWouldChange(spec.Update, spec.Upgrade, spec.Autoremove) {
		installInfos, err := infos(ctx.Host, spec.Install)
		if err != nil {
			return fmt.Errorf("%s step: %w", pluginName, err)
		}
		purgeInfos, err := infos(ctx.Host, spec.Purge)
		if err != nil {
			return fmt.Errorf("%s step: %w", pluginName, err)
		}
		wouldChange = packages.WouldChange(installInfos, purgeInfos)
	}

	for _, op := range []struct {
		mode, state, cmd, failure string
	}{
		{spec.Update, packages.StateLastUpdate, updateCmd, "package index update failed"},
		{spec.Upgrade, packages.StateLastUpgrade, upgradeCmd, "package upgrade failed"},
	} {
		run, err := packages.ShouldRun(ctx.Host, op.mode, op.state, wouldChange)
		if err != nil {
			return fmt.Errorf("%s step: %w", pluginName, err)
		}
		if !run {
			continue
		}
		if err := packages.RunRoot(ctx.Host, op.cmd); err != nil {
			return fmt.Errorf("%s: %w", op.failure, err)
		}
		if strings.HasPrefix(op.mode, "if_") {
			packages.MarkRan(ctx.Host, op.state)
		}
	}

	if len(spec.Install) > 0 {
		if err := packages.RunRoot(ctx.Host, packages.AppendPackages(installCmd, spec.Install)); err != nil {
			return fmt.Errorf("package install failed (%s): %w", strings.Join(spec.Install, ","), err)
		}
	}
	if len(spec.Purge) > 0 {
		// The preview runs against the host as apply leaves it, after the update
		// and upgrade above: a transaction resolved before those would describe a
		// dependency graph that is no longer the one being removed from.
		preview, err := purgePreview(ctx.Host, spec.Purge)
		if err != nil {
			return fmt.Errorf("preview purge transaction (%s): %w", strings.Join(spec.Purge, ","), err)
		}
		if err := packages.GuardPurgeTransaction(spec.Purge, spec.PurgeAlsoRemoves, preview); err != nil {
			return fmt.Errorf("%s step: %w", pluginName, err)
		}
		if err := packages.RunRoot(ctx.Host, packages.AppendPackages(purgeCmd, spec.Purge)); err != nil {
			return fmt.Errorf("package purge failed (%s): %w", strings.Join(spec.Purge, ","), err)
		}
	}

	runAutoremove, err := packages.ShouldRun(ctx.Host, spec.Autoremove, packages.StateLastAutoremove, wouldChange)
	if err != nil {
		return fmt.Errorf("%s step: %w", pluginName, err)
	}
	if runAutoremove {
		if err := packages.RunRoot(ctx.Host, autoremoveCmd); err != nil {
			return fmt.Errorf("package autoremove failed: %w", err)
		}
		if strings.HasPrefix(spec.Autoremove, "if_") {
			packages.MarkRan(ctx.Host, packages.StateLastAutoremove)
		}
	}
	return nil
}

func infos(host pluginapi.Host, names []string) ([]packages.PkgInfo, error) {
	out := make([]packages.PkgInfo, len(names))
	for i, name := range names {
		was, err := installed(host, name)
		if err != nil {
			return nil, err
		}
		out[i] = packages.PkgInfo{Name: name, Installed: was}
	}
	return out, nil
}

func plan(ctx pluginapi.Context, spec *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("%s plan: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		pluginName, spec.Update, spec.Upgrade, spec.Install, spec.Purge, spec.Autoremove)
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: host context is required", pluginName)
	}

	installInfos, err := infos(ctx.Host, spec.Install)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: %w", pluginName, err)
	}
	purgeInfos, err := infos(ctx.Host, spec.Purge)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: %w", pluginName, err)
	}

	in := packages.PlanInputs{
		UpdateMode:       spec.Update,
		UpgradeMode:      spec.Upgrade,
		AutoremoveMode:   spec.Autoremove,
		InstallInfos:     installInfos,
		PurgeInfos:       purgeInfos,
		PurgeAlsoRemoves: spec.PurgeAlsoRemoves,
	}
	wouldChange := packages.WouldChange(in.InstallInfos, in.PurgeInfos)

	if in.Update, err = packages.PlanOpDecision(ctx.Host, spec.Update, packages.StateLastUpdate, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid update mode: %w", pluginName, err)
	}
	if in.Upgrade, err = packages.PlanOpDecision(ctx.Host, spec.Upgrade, packages.StateLastUpgrade, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid upgrade mode: %w", pluginName, err)
	}
	if in.Autoremove, err = packages.PlanOpDecision(ctx.Host, spec.Autoremove, packages.StateLastAutoremove, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid autoremove mode: %w", pluginName, err)
	}

	if in.Upgrade.WillRun {
		pkgs, err := upgradePreview(ctx.Host)
		in.UpgradePreview = packages.Preview{Packages: pkgs, Err: err}
	}
	if len(spec.Install) > 0 {
		pkgs, err := installPreview(ctx.Host, spec.Install)
		in.InstallPreview = packages.Preview{Packages: pkgs, Err: err}
	}
	if len(spec.Purge) > 0 {
		pkgs, err := purgePreview(ctx.Host, spec.Purge)
		in.PurgePreview = packages.Preview{Packages: pkgs, Err: err}
	}
	if in.Autoremove.WillRun {
		pkgs, err := autoremovePreview(ctx.Host)
		in.AutoremovePreview = packages.Preview{Packages: pkgs, Err: err}
	}

	return packages.RenderPlan(in), nil
}

func capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if ctx.Host == nil {
		return record, fmt.Errorf("%s step: host context is required", pluginName)
	}

	names, installSet, purgeSet := packages.Targets(spec.Install, spec.Purge)
	records := make([]pluginapi.ObjectRecord, 0, len(names))
	for _, name := range names {
		was, version, pin, err := packages.RPMQuery(ctx.Host, name)
		if err != nil {
			return record, fmt.Errorf("step %q (type=%s): capture package state for %q: %w", stepID, pluginName, name, err)
		}
		_, wantInstall := installSet[name]
		_, wantPurge := purgeSet[name]
		records = append(records, pluginapi.ObjectRecord{
			Kind: pluginapi.ObjectPackage,
			Package: &pluginapi.PackageState{
				Name:             name,
				WasInstalled:     was,
				Version:          version,
				PinSpec:          pin,
				RequestedInstall: wantInstall,
				RequestedPurge:   wantPurge,
			},
		})
	}

	record.RollbackMode = pluginapi.ModeBestEffort
	record.Objects = records
	record.Notes = packages.CaptureNotes(spec.Update, spec.Upgrade, spec.Autoremove)
	return record, nil
}

func restore(host pluginapi.Host, p pluginapi.PackageState) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("package name is empty")
	}
	if err := packages.ValidateNames(nameRe, []string{name}); err != nil {
		return err
	}

	if p.RequestedInstall && !p.WasInstalled {
		// dnf resolves a removal outwards, so an unguarded undo takes whatever
		// came to depend on the package since apply along with it. Read the
		// transaction back first and stop rather than remove more than one
		// install's worth.
		preview, err := removePreview(host, []string{name})
		if err != nil {
			return fmt.Errorf("preview removal of package %q: %w", name, err)
		}
		if extra := packages.UnexpectedRemovals([]string{name}, preview); len(extra) > 0 {
			return fmt.Errorf("refusing to remove package %q: the transaction would also remove %s",
				name, strings.Join(extra, ", "))
		}
		if err := host.RunRoot(packages.AppendPackages(rollbackRemoveCmd, []string{name})); err != nil {
			return fmt.Errorf("purge package %q: %w", name, err)
		}
	}

	if p.RequestedPurge && p.WasInstalled {
		// The journalled pin is a full NEVRA, checked against that shape before
		// it reaches a root command.
		if p.PinSpec != "" && pinRe.MatchString(p.PinSpec) {
			if err := host.RunRoot(packages.AppendPackages(installCmd, []string{p.PinSpec})); err == nil {
				return nil
			}
		}
		if err := host.RunRoot(packages.AppendPackages(installCmd, []string{name})); err != nil {
			return fmt.Errorf("reinstall package %q: %w", name, err)
		}
	}

	return nil
}

func conflict(host pluginapi.Host, p pluginapi.PackageState) []string {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil
	}
	// A state that cannot be read is reported as a conflict rather than skipped:
	// rollback asks this question to find out whether reverting is still safe,
	// and "the host did not answer" is not a yes.
	current, version, _, err := packages.RPMQuery(host, name)
	if err != nil {
		return []string{fmt.Sprintf("package %q: cannot read current state: %v", name, err)}
	}
	if current != p.WasInstalled {
		return []string{fmt.Sprintf(
			"package %q: installed=%v but journal recorded installed=%v after apply (changed since apply)",
			name, current, p.WasInstalled)}
	}
	if current && p.WasInstalled && p.Version != "" && version != "" && version != p.Version {
		return []string{fmt.Sprintf(
			"package %q: version is %q but journal recorded %q after apply (upgraded since apply)",
			name, version, p.Version)}
	}
	return nil
}
