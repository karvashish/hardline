package main

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin(applyDeps ApplyDeps, rollbackDeps RollbackDeps) pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "firewall_template",
		InternalValidation: true,
		Apply: func(ctx pluginapi.ApplyContext, step profile.Step) error {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return err
			}
			return Apply(ctx, spec, applyDeps)
		},
		Plan: func(ctx pluginapi.PlanContext, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Rollback: func(ctx pluginapi.RollbackContext, step profile.Step) (pluginapi.StepRecord, error) {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "firewall_template"}, err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return pluginapi.StepRecord{ID: step.ID, Type: "firewall_template"}, err
			}

			return CaptureRollback(ctx, step.ID, spec, rollbackDeps)
		},
	}
}

func decodeFirewallTemplateSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateFirewallTemplateSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("firewall_template config is required")
	}
	if strings.TrimSpace(spec.Backend) == "" {
		return fmt.Errorf("firewall backend is required")
	}
	if spec.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", spec.Backend)
	}
	if strings.TrimSpace(spec.Policy) == "" {
		return fmt.Errorf("firewall_template policy is required")
	}

	for _, rule := range spec.Allow {
		if rule.Port <= 0 || rule.Port > 65535 {
			return fmt.Errorf("firewall_template allow port %d is out of range", rule.Port)
		}
		switch strings.ToLower(strings.TrimSpace(rule.Proto)) {
		case "", "tcp", "udp":
		default:
			return fmt.Errorf("unsupported firewall_template protocol %q", rule.Proto)
		}
	}

	return nil
}
