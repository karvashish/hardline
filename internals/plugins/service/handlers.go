package service

import (
	"fmt"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func ApplyHandler(applyFn func(pluginapi.ApplyContext, *profile.ServiceSpec) error) pluginapi.ApplyHandler {
	return pluginapi.ApplyHandler{
		Type: "service",
		Apply: func(ctx pluginapi.ApplyContext, s profile.Step) error {
			if s.Service == nil {
				return fmt.Errorf("step %q (type=%s): service spec missing", s.ID, s.Type)
			}
			return applyFn(ctx, s.Service)
		},
	}
}

func PlanHandler(planFn func(pluginapi.PlanContext, *profile.ServiceSpec) (pluginapi.PlanResult, error)) pluginapi.PlanHandler {
	return pluginapi.PlanHandler{
		Type: "service",
		Plan: func(ctx pluginapi.PlanContext, s profile.Step) (pluginapi.PlanResult, error) {
			if s.Service == nil {
				return pluginapi.PlanResult{}, fmt.Errorf("step %q (type=%s): service spec missing", s.ID, s.Type)
			}
			return planFn(ctx, s.Service)
		},
	}
}

func DefaultApplyHandler(deps ApplyDeps) pluginapi.ApplyHandler {
	h := ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.ServiceSpec) error {
		return Apply(ctx, spec, deps)
	})
	h.ValidateKinds = map[string]func(pluginapi.ApplyContext) error{
		"service": func(pluginapi.ApplyContext) error { return nil },
	}
	return h
}

func DefaultPlanHandler() pluginapi.PlanHandler {
	h := PlanHandler(Plan)
	h.ValidateKinds = map[string]func(pluginapi.PlanContext) (pluginapi.PlanResult, error){
		"service": func(pluginapi.PlanContext) (pluginapi.PlanResult, error) {
			return pluginapi.PlanResult{Summary: "service validation: no additional checks"}, nil
		},
	}
	return h
}

func DefaultRollbackHandler(deps RollbackDeps) pluginapi.RollbackHandler {
	return pluginapi.RollbackHandler{
		Type: "service",
		Capture: func(ctx pluginapi.RollbackContext, s profile.Step) (rollback.StepRecord, error) {
			return CaptureRollback(ctx, s, deps)
		},
	}
}
