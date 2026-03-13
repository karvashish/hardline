package plan

import (
	"fmt"

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

	Summary string
	Details []string
}

func planStep(client *ssh.Client, p *profile.Profile, s profile.Step) (StepPlan, error) {
	return planStepWithRegistry(registry.Shared(), client, p, s)
}

func planStepWithRegistry(reg *pluginapi.Registry, client *ssh.Client, p *profile.Profile, s profile.Step) (StepPlan, error) {
	pluginName := s.PluginName()

	plan := StepPlan{
		StepID:    s.ID,
		StepType:  pluginName,
		Severity:  s.Severity,
		RiskClass: s.RiskClass,
	}

	plugin, ok := reg.Lookup(pluginName)
	if !ok {
		plan.Summary = fmt.Sprintf("unknown or empty plugin %q (no-op in planning)", s.Plugin)
		return plan, nil
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
	}
	plan.Summary = result.Summary
	plan.Details = result.Details

	return plan, nil
}
