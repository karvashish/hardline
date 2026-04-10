package template

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "template",
		InternalValidation: true,
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeTemplateSpec(step)
			if err != nil {
				return err
			}
			if err := validateTemplateSpec(spec); err != nil {
				return err
			}
			if err := Apply(ctx, spec); err != nil {
				return err
			}
			return nil
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeTemplateSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateTemplateSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}

			result, err := Plan(ctx, spec)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}

			return result, nil
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeTemplateSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := validateTemplateSpec(spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}

			return Capture(ctx, step.ID, spec)
		},
	}
}

func decodeTemplateSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateTemplateSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("template config is required")
	}
	if strings.TrimSpace(spec.Src) == "" {
		return fmt.Errorf("template src is required")
	}
	if strings.TrimSpace(spec.Dest) == "" {
		return fmt.Errorf("template dest is required")
	}
	if mode := strings.TrimSpace(spec.Mode); mode != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(mode, "%o", &parsed); err != nil {
			return fmt.Errorf("template mode %q must be octal", spec.Mode)
		}
	}
	return nil
}
