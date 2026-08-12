package firewall

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "firewall",
		InternalValidation: true,
		Validate: func(step profile.Step, overrides map[string]json.RawMessage) error {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return err
			}
			if err := applyFirewallOverrides(overrides, spec); err != nil {
				return err
			}
			return validateFirewallSpec(spec)
		},
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return err
			}
			if err := applyFirewallOverrides(ctx.Overrides, spec); err != nil {
				return err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return err
			}
			if err := Apply(ctx, spec); err != nil {
				return err
			}
			if err := ValidateApply(ctx.Host, spec.MainConfig, spec.ManagedDest); err != nil {
				return err
			}
			// The file is in place and the composite parses; loading it is what
			// makes the kernel run it. Without this the step hardens a file and
			// leaves the running ruleset untouched.
			desired, err := NormalizeDesiredSpec(spec)
			if err != nil {
				return err
			}
			return ActivateFirewall(ctx.Host, spec.MainConfig, desired)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := applyFirewallOverrides(ctx.Overrides, spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeFirewallSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := applyFirewallOverrides(ctx.Overrides, spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := validateFirewallSpec(spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}

			return Capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectFile:
				if obj.File == nil {
					return fmt.Errorf("firewall rollback: missing file snapshot")
				}
				if ValidMainConfig(obj.File.Path) {
					return restoreNftablesMainConfig(host, *obj.File)
				}
				return pluginapi.RestoreFileSnapshot(host, *obj.File)
			case pluginapi.ObjectConfigLine:
				if obj.ConfigLine == nil {
					return fmt.Errorf("firewall rollback: missing include record")
				}
				return RestoreNftablesInclude(host, *obj.ConfigLine)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("firewall plugin cannot roll back kind %q", obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			switch {
			case after.Kind == pluginapi.ObjectFile && after.File != nil:
				return pluginapi.FileSnapshotConflict(host, *after.File)
			case after.Kind == pluginapi.ObjectConfigLine && after.ConfigLine != nil:
				return includeLineConflict(host, *after.ConfigLine)
			}
			return nil
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
	if strings.TrimSpace(spec.MainConfig) == "" {
		return fmt.Errorf("firewall main_config is required")
	}
	if !ValidMainConfig(spec.MainConfig) {
		return fmt.Errorf("unsupported firewall main_config %q (use %s or %s)", spec.MainConfig, MainConfigDebian, MainConfigRHEL)
	}
	if strings.TrimSpace(spec.ManagedDest) == "" {
		return fmt.Errorf("firewall managed_dest is required")
	}
	if _, err := NormalizeDesiredSpec(spec); err != nil {
		return err
	}
	return nil
}
