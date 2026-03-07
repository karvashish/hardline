package packages

import (
	"fmt"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func ApplyHandler(applyFn func(pluginapi.ApplyContext, *profile.PackageSpec) error) pluginapi.ApplyHandler {
	return pluginapi.ApplyHandler{
		Type: "packages",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			if s.Packages == nil {
				return fmt.Errorf("step %q (type=%s): packages spec missing", s.ID, s.Type)
			}
			return applyFn(ctx, s.Packages)
		},
	}
}

func PlanHandler(planFn func(pluginapi.PlanContext, *profile.PackageSpec) (pluginapi.PlanResult, error)) pluginapi.PlanHandler {
	return pluginapi.PlanHandler{
		Type: "packages",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			if s.Packages == nil {
				return pluginapi.PlanResult{}, fmt.Errorf("step %q (type=%s): packages spec missing", s.ID, s.Type)
			}
			return planFn(ctx, s.Packages)
		},
	}
}

func DefaultApplyHandler(deps ApplyDeps) pluginapi.ApplyHandler {
	return ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.PackageSpec) error {
		return Apply(ctx, spec, deps)
	})
}

func DefaultPlanHandler() pluginapi.PlanHandler {
	return PlanHandler(Plan)
}

func DefaultRollbackHandler(deps RollbackDeps) pluginapi.RollbackHandler {
	return pluginapi.RollbackHandler{
		Type: "packages",
		Capture: func(ctx pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
			return CaptureRollback(ctx, s, deps)
		},
	}
}
