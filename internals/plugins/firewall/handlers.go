package firewall

import (
	"fmt"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func ApplyHandler(
	applyFn func(pluginapi.ApplyContext, *profile.FirewallSpec) error,
	validateFirewall func(pluginapi.ApplyContext) error,
) pluginapi.ApplyHandler {
	h := pluginapi.ApplyHandler{
		Type: "firewall",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			if s.Firewall == nil {
				return fmt.Errorf("step %q (type=%s): firewall spec missing", s.ID, s.Type)
			}
			return applyFn(ctx, s.Firewall)
		},
	}
	if validateFirewall != nil {
		h.ValidateKinds = map[string]func(pluginapi.ApplyContext) error{
			"firewall": validateFirewall,
		}
	}
	return h
}

func PlanHandler(
	planFn func(pluginapi.PlanContext, *profile.FirewallSpec) (pluginapi.PlanResult, error),
	validateFirewall func(pluginapi.PlanContext) (pluginapi.PlanResult, error),
) pluginapi.PlanHandler {
	h := pluginapi.PlanHandler{
		Type: "firewall",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			if s.Firewall == nil {
				return pluginapi.PlanResult{}, fmt.Errorf("step %q (type=%s): firewall spec missing", s.ID, s.Type)
			}
			return planFn(ctx, s.Firewall)
		},
	}
	if validateFirewall != nil {
		h.ValidateKinds = map[string]func(pluginapi.PlanContext) (pluginapi.PlanResult, error){
			"firewall": validateFirewall,
		}
	}
	return h
}

func DefaultApplyHandler(deps ApplyDeps) pluginapi.ApplyHandler {
	return ApplyHandler(
		func(ctx pluginapi.ApplyContext, spec *profile.FirewallSpec) error {
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
		Type: "firewall",
		Capture: func(ctx pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
			return CaptureRollback(ctx, s, deps)
		},
	}
}
