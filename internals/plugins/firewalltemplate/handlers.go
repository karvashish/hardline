package firewalltemplate

import (
	"fmt"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func ApplyHandler(applyFn func(pluginapi.ApplyContext, *profile.FirewallTemplateSpec) error) pluginapi.ApplyHandler {
	return pluginapi.ApplyHandler{
		Type: "firewall_template",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			if s.FirewallTemplate == nil {
				return fmt.Errorf("step %q (type=%s): firewall_template spec missing", s.ID, s.Type)
			}
			return applyFn(ctx, s.FirewallTemplate)
		},
	}
}

func PlanHandler(planFn func(pluginapi.PlanContext, *profile.FirewallTemplateSpec) (pluginapi.PlanResult, error)) pluginapi.PlanHandler {
	return pluginapi.PlanHandler{
		Type: "firewall_template",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			if s.FirewallTemplate == nil {
				return pluginapi.PlanResult{}, fmt.Errorf("step %q (type=%s): firewall_template spec missing", s.ID, s.Type)
			}
			return planFn(ctx, s.FirewallTemplate)
		},
	}
}

func DefaultApplyHandler(deps ApplyDeps) pluginapi.ApplyHandler {
	return ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.FirewallTemplateSpec) error {
		return Apply(ctx, spec, deps)
	})
}

func DefaultPlanHandler() pluginapi.PlanHandler {
	return PlanHandler(Plan)
}

func DefaultRollbackHandler(deps RollbackDeps) pluginapi.RollbackHandler {
	return pluginapi.RollbackHandler{
		Type: "firewall_template",
		Capture: func(ctx pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
			return CaptureRollback(ctx, s, deps)
		},
	}
}
