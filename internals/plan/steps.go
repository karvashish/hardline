package plan

import (
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

type StepPlan struct {
	pluginapi.PlanResult
	StepID   string
	StepType string
}

func planStepWithRegistry(reg *pluginapi.Registry, client *remote.Client, p *profile.Profile, s profile.Step, stepChanges map[string]bool) (StepPlan, error) {
	plan := StepPlan{
		StepID:   s.ID,
		StepType: s.PluginName(),
	}

	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return plan, err
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return plan, err
	}

	result, err := plugin.Plan(remote.BuildContext(client, p, stepChanges), s)
	if err != nil {
		return plan, err
	}
	if !plugin.InternalValidation && s.AllowUnvalidated {
		result.Details = append(result.Details, "validation: explicitly disabled for this step (allow_unvalidated=true)")
		result.Highlights = append(result.Highlights, "validation is explicitly disabled for this step (allow_unvalidated=true)")
	}
	plan.PlanResult = result

	return plan, nil
}
