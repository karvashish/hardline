package filemeta

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "file_meta",
		InternalValidation: true,
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeSpec(step)
			if err != nil {
				return err
			}
			if err := validateSpec(spec); err != nil {
				return err
			}
			return Apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			if err := validateSpec(spec); err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			if err := validateSpec(spec); err != nil {
				return pluginapi.CaptureResult{}, err
			}
			return Capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectFileMeta:
				if obj.FileMeta == nil {
					return fmt.Errorf("file_meta rollback: missing file metadata snapshot")
				}
				return restoreFileMeta(host, *obj.FileMeta)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("file_meta plugin cannot roll back kind %q", obj.Kind)
			}
		},
		DetectConflict: func(host pluginapi.Host, after pluginapi.ObjectRecord) []string {
			if after.Kind == pluginapi.ObjectFileMeta && after.FileMeta != nil {
				return fileMetaConflict(host, *after.FileMeta)
			}
			return nil
		},
	}
}

func decodeSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("file_meta config is required")
	}
	if _, err := enforceAbsCleanPath(spec.Path); err != nil {
		return fmt.Errorf("file_meta: %w", err)
	}
	if strings.TrimSpace(spec.Mode) != "" {
		if _, err := normalizeMode(spec.Mode); err != nil {
			return fmt.Errorf("file_meta: %w", err)
		}
	}
	if strings.TrimSpace(spec.Mode) == "" &&
		strings.TrimSpace(spec.Owner) == "" &&
		strings.TrimSpace(spec.Group) == "" &&
		spec.Immutable == nil &&
		spec.AppendOnly == nil {
		return fmt.Errorf("file_meta: at least one of mode, owner, group, immutable, append_only must be set")
	}
	return nil
}
