package template

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "template",
		InternalValidation: true,
		Validate: func(step profile.Step, _ map[string]json.RawMessage) error {
			spec, err := decodeTemplateSpec(step)
			if err != nil {
				return err
			}
			return validateTemplateSpec(spec)
		},
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
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectFile:
				if obj.File == nil {
					return fmt.Errorf("template rollback: missing file snapshot")
				}
				return pluginapi.RestoreFileSnapshot(host, *obj.File)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("template plugin cannot roll back kind %q", obj.Kind)
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
	// Mode is required rather than defaulted. Sscanf used to accept "644xyz"
	// and out-of-range values, and an implicit 0600 meant a profile that forgot
	// the field silently got a mode nobody declared.
	if _, err := pluginapi.ParseFileMode(spec.Mode); err != nil {
		return fmt.Errorf("template dest %q: %w", spec.Dest, err)
	}
	return nil
}
