package ssh

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plugin() pluginapi.Plugin {
	return pluginapi.Plugin{
		Name:               "ssh",
		InternalValidation: true,
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
					return fmt.Errorf("ssh rollback: missing file snapshot")
				}
				unit, err := ServiceUnit(obj)
				if err != nil {
					return err
				}
				return Restore(host, *obj.File, unit)
			case pluginapi.ObjectValidate:
				return nil
			default:
				return fmt.Errorf("ssh plugin cannot roll back kind %q", obj.Kind)
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
		return fmt.Errorf("ssh config is required")
	}
	if strings.TrimSpace(spec.Path) == "" {
		return fmt.Errorf("ssh path is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Path); err != nil {
		return err
	}
	if !strings.HasPrefix(spec.Path, "/etc/ssh/sshd_config.d/") {
		return fmt.Errorf("ssh path %q must be under /etc/ssh/sshd_config.d/, which is what sshd includes", spec.Path)
	}
	switch spec.Service {
	case "ssh", "sshd":
	case "":
		return fmt.Errorf("ssh service is required: it is \"ssh\" on Debian and Ubuntu and \"sshd\" on the RHEL family")
	default:
		return fmt.Errorf("ssh service %q is not one of ssh, sshd", spec.Service)
	}
	if _, err := pluginapi.ParseFileMode(spec.Mode); err != nil {
		return fmt.Errorf("ssh step: %w", err)
	}
	if _, err := ParseSettings(spec.Settings); err != nil {
		return err
	}
	for i, mc := range spec.VerifyContexts {
		if strings.TrimSpace(mc.User) == "" || strings.TrimSpace(mc.Host) == "" || strings.TrimSpace(mc.Address) == "" {
			return fmt.Errorf("ssh verify_contexts[%d] must set user, host and addr: sshd needs all three to evaluate Match", i)
		}
		if strings.ContainsAny(mc.User+mc.Host+mc.Address, " \t,=") {
			return fmt.Errorf("ssh verify_contexts[%d] contains a space, comma or equals sign, which sshd -T -C cannot express", i)
		}
	}
	return nil
}
