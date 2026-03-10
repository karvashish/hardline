package packages

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin(applyDeps ApplyDeps, rollbackDeps RollbackDeps) pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "packages",
		InternalValidation: true,
		Apply: func(ctx pluginapi.ApplyContext, step profile.Step) error {
			spec, err := decodePackageSpec(step)
			if err != nil {
				return err
			}
			if err := validatePackageSpec(spec); err != nil {
				return err
			}
			return Apply(ctx, spec, applyDeps)
		},
		Plan: func(ctx pluginapi.PlanContext, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodePackageSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validatePackageSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Rollback: func(ctx pluginapi.RollbackContext, step profile.Step) (pluginapi.StepRecord, error) {
			spec, err := decodePackageSpec(step)
			if err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "packages"}, err
			}
			if err := validatePackageSpec(spec); err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "packages"}, err
			}

			return CaptureRollback(ctx, step.ID, spec, rollbackDeps)
		},
	}
}

func decodePackageSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validatePackageSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("packages config is required")
	}

	install := make(map[string]struct{}, len(spec.Install))
	for _, raw := range spec.Install {
		name := strings.TrimSpace(raw)
		if name == "" {
			return fmt.Errorf("packages install entries must not be empty")
		}
		if _, exists := install[name]; exists {
			return fmt.Errorf("package %q is duplicated in install list", name)
		}
		install[name] = struct{}{}
	}

	purge := make(map[string]struct{}, len(spec.Purge))
	for _, raw := range spec.Purge {
		name := strings.TrimSpace(raw)
		if name == "" {
			return fmt.Errorf("packages purge entries must not be empty")
		}
		if _, exists := purge[name]; exists {
			return fmt.Errorf("package %q is duplicated in purge list", name)
		}
		purge[name] = struct{}{}
		if _, exists := install[name]; exists {
			return fmt.Errorf("package %q cannot be both installed and purged in one step", name)
		}
	}

	return nil
}
