package plan

import (
	"fmt"
	"strings"

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
	stepType := strings.ToLower(strings.TrimSpace(s.Type))

	plan := StepPlan{
		StepID:    s.ID,
		StepType:  stepType,
		Severity:  s.Severity,
		RiskClass: s.RiskClass,
	}

	if stepType == "validate" {
		kind := strings.TrimSpace(s.Validate)
		if kind == "" {
			return plan, fmt.Errorf("step %q (type=%s): validate spec missing", s.ID, s.Type)
		}
		summary, details, err := planValidate(insp, kind)
		if err != nil {
			return plan, err
		}
		plan.Summary = summary
		plan.Details = details
		return plan, nil
	}

	handler, ok := planActionRegistry.LookupType(stepType)
	if !ok {
		plan.Summary = fmt.Sprintf("unknown or empty step type %q (no-op in planning)", s.Type)
		return plan, nil
	}

	result, err := handler.Plan(planActionContext(insp, p), s)
	if err != nil {
		return plan, err
	}
	plan.Summary = result.Summary
	plan.Details = result.Details
	switch result.Noop {
	case 1:
		plan.Severity = "medium"
	case 0:
		plan.Severity = "low"
	}

	return plan, nil
}

func planValidate(insp inspector.Inspector, kind string) (string, []string, error) {
	validateFn, ok := planActionRegistry.LookupValidate(kind)
	if !ok {
		summary := fmt.Sprintf("validate step: unsupported kind %q", kind)
		return summary, []string{"no validation logic implemented for this kind"}, nil
	}

	result, err := validateFn(pluginapi.PlanContext{Inspector: insp})
	if err != nil {
		return "", nil, err
	}
	return result.Summary, result.Details, nil
}
