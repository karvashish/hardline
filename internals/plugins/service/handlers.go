package service

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name: "service",
		Validate: func(step profile.Step, _ map[string]json.RawMessage) error {
			spec, err := decodeServiceSpec(step)
			if err != nil {
				return err
			}
			return validateServiceSpec(spec)
		},
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeServiceSpec(step)
			if err != nil {
				return err
			}
			if err := validateServiceSpec(spec); err != nil {
				return err
			}
			return Apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeServiceSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateServiceSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeServiceSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := validateServiceSpec(spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}

			return Capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectService:
				if obj.Service == nil {
					return fmt.Errorf("service rollback: missing service snapshot")
				}
				return restoreServiceState(host, *obj.Service)
			default:
				return fmt.Errorf("service plugin cannot roll back kind %q", obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			if after.Kind == pluginapi.ObjectService && after.Service != nil {
				return serviceStateConflict(host, *after.Service)
			}
			return nil
		},
	}
}

func decodeServiceSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateServiceSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("service config is required")
	}
	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("service name is required")
	}
	if err := validateServiceUnit(strings.TrimSpace(spec.Name)); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(spec.State)) {
	case "", "started", "start", "stopped", "stop", "restarted", "restart", "reloaded", "reload", "reload-or-restart":
	default:
		return fmt.Errorf("unsupported service state %q for %s", spec.State, strings.TrimSpace(spec.Name))
	}

	return validateRestartPolicy(spec)
}

func validateRestartPolicy(spec *Spec) error {
	p := spec.RestartPolicy
	if p == nil {
		return nil
	}

	unit := strings.TrimSpace(spec.Name)
	switch strings.ToLower(strings.TrimSpace(p.Type)) {
	case "always":
		if len(p.Steps) > 0 {
			return fmt.Errorf("service %s: restart_policy type \"always\" must not declare steps", unit)
		}
	case "on_change":
		if len(p.Steps) == 0 {
			return fmt.Errorf("service %s: restart_policy type \"on_change\" requires at least one step to watch", unit)
		}
		seen := make(map[string]struct{}, len(p.Steps))
		for _, id := range p.Steps {
			trimmed := strings.TrimSpace(id)
			if trimmed == "" {
				return fmt.Errorf("service %s: restart_policy steps contains an empty step ID", unit)
			}
			if _, dup := seen[trimmed]; dup {
				return fmt.Errorf("service %s: restart_policy steps contains duplicate %q", unit, trimmed)
			}
			seen[trimmed] = struct{}{}
		}
	default:
		return fmt.Errorf("service %s: unsupported restart_policy type %q (expected \"always\" or \"on_change\")", unit, p.Type)
	}

	if strings.TrimSpace(spec.State) == "" {
		return fmt.Errorf("service %s: restart_policy requires a state to apply it to", unit)
	}
	return nil
}
