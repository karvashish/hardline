package packages

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

type Spec struct {
	Update           string   `json:"update,omitempty"`
	Upgrade          string   `json:"upgrade,omitempty"`
	Autoremove       string   `json:"autoremove,omitempty"`
	Install          []string `json:"install"`
	Purge            []string `json:"purge"`
	PurgeAlsoRemoves []string `json:"purge_also_removes,omitempty"`
}

type QueryFunc func(pluginapi.Host, string) (bool, string, string, error)

type PackagesPreviewFunc func(pluginapi.Host, []string) ([]string, error)

type OperationPreviewFunc func(pluginapi.Host) ([]string, error)

type Commands struct {
	Update         string
	Upgrade        string
	Install        string
	Purge          string
	Autoremove     string
	RollbackRemove string
}

type Previews struct {
	Upgrade        OperationPreviewFunc
	Install        PackagesPreviewFunc
	Purge          PackagesPreviewFunc
	Autoremove     OperationPreviewFunc
	RollbackRemove PackagesPreviewFunc
}

type Backend struct {
	Name        string
	NamePattern *regexp.Regexp
	PinPattern  *regexp.Regexp
	CheckLock   func(pluginapi.Host) error
	Query       QueryFunc
	Commands    Commands
	Previews    Previews
}

func (b Backend) Plugin() pluginapi.Plugin {
	if err := b.validateConfiguration(); err != nil {
		panic(fmt.Sprintf("invalid package backend: %v", err))
	}
	return pluginapi.Plugin{
		Name: b.Name,
		Validate: func(step profile.Step, _ map[string]json.RawMessage) error {
			_, err := b.decode(step)
			return err
		},
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := b.decode(step)
			if err != nil {
				return err
			}
			return b.apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := b.decode(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return b.plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := b.decode(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			return b.capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectPackage:
				if obj.Package == nil {
					return fmt.Errorf("%s rollback: missing package snapshot", b.Name)
				}
				return b.restore(host, *obj.Package)
			default:
				return fmt.Errorf("%s plugin cannot roll back kind %q", b.Name, obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			if after.Kind == pluginapi.ObjectPackage && after.Package != nil {
				return b.conflict(host, *after.Package)
			}
			return nil
		},
	}
}

func (b Backend) validateConfiguration() error {
	if strings.TrimSpace(b.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if b.NamePattern == nil {
		return fmt.Errorf("%s: package-name pattern is required", b.Name)
	}
	if b.PinPattern == nil {
		return fmt.Errorf("%s: package-pin pattern is required", b.Name)
	}
	if b.CheckLock == nil {
		return fmt.Errorf("%s: lock check is required", b.Name)
	}
	if b.Query == nil {
		return fmt.Errorf("%s: package query is required", b.Name)
	}
	for _, command := range []struct {
		name, value string
	}{
		{"update", b.Commands.Update},
		{"upgrade", b.Commands.Upgrade},
		{"install", b.Commands.Install},
		{"purge", b.Commands.Purge},
		{"autoremove", b.Commands.Autoremove},
	} {
		if strings.TrimSpace(command.value) == "" {
			return fmt.Errorf("%s: %s command is required", b.Name, command.name)
		}
	}
	if b.Previews.Upgrade == nil {
		return fmt.Errorf("%s: upgrade preview is required", b.Name)
	}
	if b.Previews.Install == nil {
		return fmt.Errorf("%s: install preview is required", b.Name)
	}
	if b.Previews.Purge == nil {
		return fmt.Errorf("%s: purge preview is required", b.Name)
	}
	if b.Previews.Autoremove == nil {
		return fmt.Errorf("%s: autoremove preview is required", b.Name)
	}
	hasRollbackCommand := strings.TrimSpace(b.Commands.RollbackRemove) != ""
	hasRollbackPreview := b.Previews.RollbackRemove != nil
	if hasRollbackCommand != hasRollbackPreview {
		return fmt.Errorf("%s: rollback removal command and preview must be configured together", b.Name)
	}
	return nil
}

func (b Backend) decode(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	if spec.Update == "" && spec.Upgrade == "" && spec.Autoremove == "" &&
		len(spec.Install) == 0 && len(spec.Purge) == 0 {
		return nil, fmt.Errorf("%s config is required", b.Name)
	}
	if err := b.validate(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func (b Backend) validate(spec *Spec) error {
	for _, op := range []struct{ field, val string }{
		{"update", spec.Update},
		{"upgrade", spec.Upgrade},
		{"autoremove", spec.Autoremove},
	} {
		if err := ValidateOpMode(op.field, op.val); err != nil {
			return err
		}
	}
	// It also bounds the autoremove, which runs without a purge.
	if len(spec.PurgeAlsoRemoves) > 0 && len(spec.Purge) == 0 && (spec.Autoremove == "" || spec.Autoremove == "never") {
		return fmt.Errorf("%s: purge_also_removes has no effect without purge or autoremove", b.Name)
	}
	if err := ValidatePurgeCollateral(spec.Install, spec.Purge, spec.PurgeAlsoRemoves); err != nil {
		return err
	}
	if err := ValidateNames(b.NamePattern, spec.PurgeAlsoRemoves); err != nil {
		return err
	}
	return ValidateLists(b.NamePattern, spec.Install, spec.Purge)
}

func (b Backend) infos(host pluginapi.Host, names []string) ([]PkgInfo, error) {
	out := make([]PkgInfo, len(names))
	for i, name := range names {
		was, _, _, err := b.Query(host, name)
		if err != nil {
			return nil, err
		}
		out[i] = PkgInfo{Name: name, Installed: was}
	}
	return out, nil
}

func (b Backend) apply(ctx pluginapi.Context, spec *Spec) error {
	logger.Debugf("%s: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		b.Name, spec.Update, spec.Upgrade, spec.Install, spec.Purge, spec.Autoremove)
	if ctx.Host == nil {
		return fmt.Errorf("%s step: host context is required", b.Name)
	}
	if err := b.CheckLock(ctx.Host); err != nil {
		return fmt.Errorf("%s step: %w", b.Name, err)
	}

	wouldChange := false
	if NeedsWouldChange(spec.Update, spec.Upgrade, spec.Autoremove) {
		installInfos, err := b.infos(ctx.Host, spec.Install)
		if err != nil {
			return fmt.Errorf("%s step: %w", b.Name, err)
		}
		purgeInfos, err := b.infos(ctx.Host, spec.Purge)
		if err != nil {
			return fmt.Errorf("%s step: %w", b.Name, err)
		}
		wouldChange = WouldChange(installInfos, purgeInfos)
	}

	for _, op := range []struct {
		mode, state, cmd, failure string
	}{
		{spec.Update, StateLastUpdate, b.Commands.Update, "package index update failed"},
		{spec.Upgrade, StateLastUpgrade, b.Commands.Upgrade, "package upgrade failed"},
	} {
		run, err := ShouldRun(ctx.Host, op.mode, op.state, wouldChange)
		if err != nil {
			return fmt.Errorf("%s step: %w", b.Name, err)
		}
		if !run {
			continue
		}
		if err := RunRoot(ctx.Host, op.cmd); err != nil {
			return fmt.Errorf("%s: %w", op.failure, err)
		}
		if strings.HasPrefix(op.mode, "if_") {
			MarkRan(ctx.Host, op.state)
		}
	}

	if len(spec.Install) > 0 {
		if err := RunRoot(ctx.Host, AppendPackages(b.Commands.Install, spec.Install)); err != nil {
			return fmt.Errorf("package install failed (%s): %w", strings.Join(spec.Install, ","), err)
		}
	}
	if len(spec.Purge) > 0 {
		preview, err := b.Previews.Purge(ctx.Host, spec.Purge)
		if err != nil {
			return fmt.Errorf("preview purge transaction (%s): %w", strings.Join(spec.Purge, ","), err)
		}
		if err := GuardPurgeTransaction(spec.Purge, spec.PurgeAlsoRemoves, preview); err != nil {
			return fmt.Errorf("%s step: %w", b.Name, err)
		}
		if err := RunRoot(ctx.Host, AppendPackages(b.Commands.Purge, spec.Purge)); err != nil {
			return fmt.Errorf("package purge failed (%s): %w", strings.Join(spec.Purge, ","), err)
		}
	}

	runAutoremove, err := ShouldRun(ctx.Host, spec.Autoremove, StateLastAutoremove, wouldChange)
	if err != nil {
		return fmt.Errorf("%s step: %w", b.Name, err)
	}
	if runAutoremove {
		// Capture only journals the declared names, so anything else autoremove takes is gone for good.
		preview, err := b.Previews.Autoremove(ctx.Host)
		if err != nil {
			return fmt.Errorf("preview autoremove transaction: %w", err)
		}
		declared := append(append([]string(nil), spec.Purge...), spec.PurgeAlsoRemoves...)
		if extra := UnexpectedRemovals(declared, preview); len(extra) > 0 {
			return fmt.Errorf(
				"%s step: refusing to autoremove: the transaction would remove %s, which this step never declared and no capture recorded; list them in purge_also_removes to accept this",
				b.Name, strings.Join(extra, ", "))
		}
		if err := RunRoot(ctx.Host, b.Commands.Autoremove); err != nil {
			return fmt.Errorf("package autoremove failed: %w", err)
		}
		if strings.HasPrefix(spec.Autoremove, "if_") {
			MarkRan(ctx.Host, StateLastAutoremove)
		}
	}
	return nil
}

func (b Backend) plan(ctx pluginapi.Context, spec *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("%s plan: update=%q upgrade=%q install=%v purge=%v autoremove=%q\n",
		b.Name, spec.Update, spec.Upgrade, spec.Install, spec.Purge, spec.Autoremove)
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: host context is required", b.Name)
	}

	installInfos, err := b.infos(ctx.Host, spec.Install)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: %w", b.Name, err)
	}
	purgeInfos, err := b.infos(ctx.Host, spec.Purge)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: %w", b.Name, err)
	}

	in := PlanInputs{
		UpdateMode:       spec.Update,
		UpgradeMode:      spec.Upgrade,
		AutoremoveMode:   spec.Autoremove,
		InstallInfos:     installInfos,
		PurgeInfos:       purgeInfos,
		PurgeAlsoRemoves: spec.PurgeAlsoRemoves,
	}
	wouldChange := WouldChange(in.InstallInfos, in.PurgeInfos)

	if in.Update, err = PlanOpDecision(ctx.Host, spec.Update, StateLastUpdate, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid update mode: %w", b.Name, err)
	}
	if in.Upgrade, err = PlanOpDecision(ctx.Host, spec.Upgrade, StateLastUpgrade, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid upgrade mode: %w", b.Name, err)
	}
	if in.Autoremove, err = PlanOpDecision(ctx.Host, spec.Autoremove, StateLastAutoremove, wouldChange); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("%s step: invalid autoremove mode: %w", b.Name, err)
	}

	if in.Upgrade.WillRun {
		pkgs, previewErr := b.Previews.Upgrade(ctx.Host)
		in.UpgradePreview = Preview{Packages: pkgs, Err: previewErr}
	}
	if len(spec.Install) > 0 {
		pkgs, previewErr := b.Previews.Install(ctx.Host, spec.Install)
		in.InstallPreview = Preview{Packages: pkgs, Err: previewErr}
	}
	if len(spec.Purge) > 0 {
		pkgs, previewErr := b.Previews.Purge(ctx.Host, spec.Purge)
		in.PurgePreview = Preview{Packages: pkgs, Err: previewErr}
	}
	if in.Autoremove.WillRun {
		pkgs, previewErr := b.Previews.Autoremove(ctx.Host)
		in.AutoremovePreview = Preview{Packages: pkgs, Err: previewErr}
	}

	return RenderPlan(in), nil
}

func (b Backend) capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if ctx.Host == nil {
		return record, fmt.Errorf("%s step: host context is required", b.Name)
	}

	purgeTargets := append(append([]string(nil), spec.Purge...), spec.PurgeAlsoRemoves...)
	names, installSet, purgeSet := Targets(spec.Install, purgeTargets)
	// Only the declared purge list reaches the purge command; collateral goes with it and cannot be removed on its own.
	_, _, declaredPurgeSet := Targets(nil, spec.Purge)
	records := make([]pluginapi.ObjectRecord, 0, len(names))
	purgesInstalled := false
	for _, name := range names {
		was, version, pin, err := b.Query(ctx.Host, name)
		if err != nil {
			return record, fmt.Errorf("step %q (type=%s): capture package state for %q: %w", stepID, b.Name, name, err)
		}
		_, wantInstall := installSet[name]
		_, wantPurge := purgeSet[name]
		if _, declared := declaredPurgeSet[name]; declared && was {
			purgesInstalled = true
		}
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

	record.RollbackMode = capturedRollbackMode(spec, purgesInstalled)
	record.Objects = records
	record.Notes = CaptureNotes(spec.Update, spec.Upgrade, spec.Autoremove)
	return record, nil
}

// The journal has to promise what Plan promised: a step that only refreshes metadata removes
// nothing, so recording best_effort for it would understate a rollback that is exact.
func capturedRollbackMode(spec *Spec, purgesInstalled bool) string {
	if purgesInstalled {
		return pluginapi.ModeIrreversible
	}
	mayRun := func(mode string) bool { return mode != "" && mode != "never" }
	if len(spec.Install) > 0 || mayRun(spec.Upgrade) || mayRun(spec.Autoremove) {
		return pluginapi.ModeBestEffort
	}
	return pluginapi.ModeDeterministic
}

func (b Backend) rollbackPreview() PackagesPreviewFunc {
	if b.Previews.RollbackRemove != nil {
		return b.Previews.RollbackRemove
	}
	return b.Previews.Purge
}

func (b Backend) rollbackRemoveCommand() string {
	if b.Commands.RollbackRemove != "" {
		return b.Commands.RollbackRemove
	}
	return b.Commands.Purge
}

func (b Backend) restore(host pluginapi.Host, p pluginapi.PackageState) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("package name is empty")
	}
	if err := ValidateNames(b.NamePattern, []string{name}); err != nil {
		return err
	}

	if p.RequestedInstall && !p.WasInstalled {
		preview, err := b.rollbackPreview()(host, []string{name})
		if err != nil {
			return fmt.Errorf("preview removal of package %q: %w", name, err)
		}
		if extra := UnexpectedRemovals([]string{name}, preview); len(extra) > 0 {
			return fmt.Errorf("refusing to remove package %q: the transaction would also remove %s",
				name, strings.Join(extra, ", "))
		}
		if err := host.RunRoot(AppendPackages(b.rollbackRemoveCommand(), []string{name})); err != nil {
			return fmt.Errorf("purge package %q: %w", name, err)
		}
	}

	if p.RequestedPurge && p.WasInstalled {
		if p.PinSpec != "" && b.PinPattern.MatchString(p.PinSpec) {
			if err := host.RunRoot(AppendPackages(b.Commands.Install, []string{p.PinSpec})); err == nil {
				return nil
			}
		}
		if err := host.RunRoot(AppendPackages(b.Commands.Install, []string{name})); err != nil {
			return fmt.Errorf("reinstall package %q: %w", name, err)
		}
	}

	return nil
}

func (b Backend) conflict(host pluginapi.Host, p pluginapi.PackageState) []string {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil
	}
	current, version, _, err := b.Query(host, name)
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
