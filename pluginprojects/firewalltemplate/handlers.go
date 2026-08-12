package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "firewall_template",
		InternalValidation: true,
		Validate: func(step profile.Step, _ map[string]json.RawMessage) error {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return err
			}
			return validateFirewallTemplateSpec(spec)
		},
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return err
			}
			return Apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeFirewallTemplateSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := validateFirewallTemplateSpec(spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}

			return Capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectFile:
				if obj.File == nil {
					return fmt.Errorf("firewall_template rollback: missing file snapshot")
				}
				if validMainConfig(obj.File.Path) {
					return restoreMainConfig(host, *obj.File)
				}
				return pluginapi.RestoreFileSnapshot(host, *obj.File)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("firewall_template plugin cannot roll back kind %q", obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			if after.Kind == pluginapi.ObjectFile && after.File != nil {
				return pluginapi.FileSnapshotConflict(host, *after.File)
			}
			return nil
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
	if strings.TrimSpace(spec.MainConfig) == "" {
		return fmt.Errorf("firewall_template main_config is required")
	}
	if !validMainConfig(spec.MainConfig) {
		return fmt.Errorf("unsupported firewall_template main_config %q (use %s or %s)", spec.MainConfig, MainConfigDebian, MainConfigRHEL)
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
