package service

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "service",
		InternalValidation: true,
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
			case pluginapi.ObjectValidate:
				return nil
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
	if err := validateServiceUnit(normalizeServiceUnit(spec.Name)); err != nil {
		return err
	}

	switch strings.ToLower(strings.TrimSpace(spec.State)) {
	case "", "started", "start", "stopped", "stop", "restarted", "restart", "reloaded", "reload", "reload-or-restart":
		return nil
	default:
		return fmt.Errorf("unsupported service state %q for %s", spec.State, strings.TrimSpace(spec.Name))
	}
}
