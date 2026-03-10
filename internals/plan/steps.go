package plan

import (
	"fmt"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

type StepPlan struct {
	StepID    string
	StepType  string
	Severity  string
	RiskClass string

	Summary string
	Details []string
}

func planStep(insp inspector.Inspector, p *profile.Profile, s profile.Step) (StepPlan, error) {
	pluginName := s.PluginName()

	plan := StepPlan{
		StepID:    s.ID,
		StepType:  pluginName,
		Severity:  s.Severity,
		RiskClass: s.RiskClass,
	}

	plugin, ok := planPluginRegistry.Lookup(pluginName)
	if !ok {
		plan.Summary = fmt.Sprintf("unknown or empty plugin %q (no-op in planning)", s.Plugin)
		return plan, nil
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return plan, err
	}

	result, err := plugin.Plan(planActionContext(insp, p), s)
	if err != nil {
		return plan, err
	}
	if !plugin.InternalValidation && s.AllowUnvalidated {
		result.Details = append(result.Details, "validation: explicitly disabled for this step (allow_unvalidated=true)")
	}
	plan.Summary = result.Summary
	plan.Details = result.Details

	return plan, nil
}
