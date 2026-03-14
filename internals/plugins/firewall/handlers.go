package firewall

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "firewall",
		InternalValidation: true,
		Apply: func(ctx pluginapi.ApplyContext, step profile.Step) error {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return err
			}
			if err := Apply(ctx, spec); err != nil {
				return err
			}
			return ValidateApply(ctx.Host)
		},
		Plan: func(ctx pluginapi.PlanContext, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}

			result, err := Plan(ctx, spec)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}

			validateResult, err := ValidatePlan(ctx.Host)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			result.Details = append(result.Details, validateResult.Details...)
			return result, nil
		},
		Rollback: func(ctx pluginapi.RollbackContext, step profile.Step) (pluginapi.StepRecord, error) {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "firewall"}, err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "firewall"}, err
			}

			return CaptureRollback(ctx, step.ID, spec)
		},
	}
}

func decodeFirewallSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateFirewallSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("firewall config is required")
	}
	if strings.TrimSpace(spec.Backend) == "" {
		return fmt.Errorf("firewall backend is required")
	}
	if spec.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", spec.Backend)
	}
	if strings.TrimSpace(spec.ManagedDest) == "" {
		return fmt.Errorf("firewall managed_dest is required")
	}
	if _, err := NormalizeDesiredSpec(spec); err != nil {
		return err
	}
	return nil
}
