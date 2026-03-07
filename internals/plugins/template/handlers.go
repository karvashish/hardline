package template

import (
	"fmt"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func ApplyHandler(
	applyFn func(pluginapi.ApplyContext, *profile.TemplateSpec) error,
	validateSSHD func(pluginapi.ApplyContext) error,
) pluginapi.ApplyHandler {
	h := pluginapi.ApplyHandler{
		Type: "template",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			if s.Template == nil {
				return fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
			}
			return applyFn(ctx, s.Template)
		},
	}
	if validateSSHD != nil {
		h.ValidateKinds = map[string]func(pluginapi.ApplyContext) error{
			"sshd": validateSSHD,
		}
	}
	return h
}

func PlanHandler(
	planFn func(pluginapi.PlanContext, *profile.TemplateSpec) (pluginapi.PlanResult, error),
	validateSSHD func(pluginapi.PlanContext) (pluginapi.PlanResult, error),
) pluginapi.PlanHandler {
	h := pluginapi.PlanHandler{
		Type: "template",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			if s.Template == nil {
				return pluginapi.PlanResult{}, fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
			}
			return planFn(ctx, s.Template)
		},
	}
	if validateSSHD != nil {
		h.ValidateKinds = map[string]func(pluginapi.PlanContext) (pluginapi.PlanResult, error){
			"sshd": validateSSHD,
		}
	}
	return h
}

func DefaultApplyHandler(deps ApplyDeps) pluginapi.ApplyHandler {
	return ApplyHandler(
		func(ctx pluginapi.ApplyContext, spec *profile.TemplateSpec) error {
			return Apply(ctx, spec, deps)
		},
		func(ctx pluginapi.ApplyContext) error {
			return ValidateApply(ctx, deps.RunRoot)
		},
	)
}

func DefaultPlanHandler() pluginapi.PlanHandler {
	return PlanHandler(Plan, ValidatePlan)
}

func DefaultRollbackHandler(deps RollbackDeps) pluginapi.RollbackHandler {
	return pluginapi.RollbackHandler{
		Type: "template",
		Capture: func(ctx pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
			return CaptureRollback(ctx, s, deps)
		},
	}
}
