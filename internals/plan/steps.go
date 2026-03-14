package plan

import (
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

type StepPlan struct {
	StepID    string
	StepType  string
	Severity  string
	RiskClass string
	Noop      int

	Summary         string
	Details         []string
	Diff            []string
	OperatorSummary string
	Highlights      []string
}

func planStep(client *ssh.Client, p *profile.Profile, s profile.Step) (StepPlan, error) {
	return planStepWithRegistry(registry.Shared(), client, p, s)
}

func planStepWithRegistry(reg *pluginapi.Registry, client *ssh.Client, p *profile.Profile, s profile.Step) (StepPlan, error) {
	plan := StepPlan{
		StepID:    s.ID,
		StepType:  s.PluginName(),
		Severity:  s.Severity,
		RiskClass: s.RiskClass,
	}

	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return plan, err
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return plan, err
	}

	result, err := plugin.Plan(planActionContext(client, p), s)
	if err != nil {
		return plan, err
	}
	if !plugin.InternalValidation && s.AllowUnvalidated {
		result.Details = append(result.Details, "validation: explicitly disabled for this step (allow_unvalidated=true)")
		result.Highlights = append(result.Highlights, "validation is explicitly disabled for this step (allow_unvalidated=true)")
	}
	plan.Noop = result.Noop
	plan.Summary = result.Summary
	plan.Details = result.Details
	plan.Diff = result.Diff
	plan.OperatorSummary = result.OperatorSummary
	plan.Highlights = result.Highlights

	return plan, nil
}
