package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name: "audit",
		Validate: func(step profile.Step, _ map[string]json.RawMessage) error {
			_, err := decodeSpec(step)
			return err
		},
		Apply: func(ctx pluginapi.Context, step profile.Step) error {
			spec, err := decodeSpec(step)
			if err != nil {
				return err
			}
			return Apply(ctx, spec)
		},
		Plan: func(ctx pluginapi.Context, step profile.Step) (pluginapi.PlanResult, error) {
			spec, err := decodeSpec(step)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return Plan(ctx, spec)
		},
		Capture: func(ctx pluginapi.Context, step profile.Step) (pluginapi.CaptureResult, error) {
			spec, err := decodeSpec(step)
			if err != nil {
				return pluginapi.CaptureResult{}, err
			}
			return Capture(ctx, step.ID, spec)
		},
		Rollback: func(host pluginapi.Host, obj pluginapi.ObjectRecord) error {
			switch obj.Kind {
			case pluginapi.ObjectFile:
				if obj.File == nil {
					return fmt.Errorf("audit rollback: missing file snapshot")
				}
				return Restore(host, *obj.File)
			default:
				return fmt.Errorf("audit plugin cannot roll back kind %q", obj.Kind)
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

func decodeSpec(step profile.Step) (*Spec, error) {
	var spec Spec
	if err := step.Decode(&spec); err != nil {
		return nil, err
	}
	if err := validateSpec(&spec); err != nil {
		return nil, err
	}
	return &spec, nil
}

func validateSpec(spec *Spec) error {
	if spec == nil {
		return fmt.Errorf("audit config is required")
	}
	if strings.TrimSpace(spec.Src) == "" {
		return fmt.Errorf("audit src is required")
	}
	if strings.TrimSpace(spec.Dest) == "" {
		return fmt.Errorf("audit dest is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Dest); err != nil {
		return err
	}
	if !strings.HasPrefix(spec.Dest, "/etc/audit/rules.d/") {
		return fmt.Errorf("audit dest %q must be under /etc/audit/rules.d/, which is what augenrules compiles", spec.Dest)
	}
	if _, err := pluginapi.ParseFileMode(spec.Mode); err != nil {
		return fmt.Errorf("audit step: %w", err)
	}
	return nil
}
