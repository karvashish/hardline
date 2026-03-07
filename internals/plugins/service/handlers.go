package service

import (
	"fmt"

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
