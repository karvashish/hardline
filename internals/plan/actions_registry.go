package plan

import (
	"fmt"

	"github.com/karvashish/hardline/internals/apply"
	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var planPluginRegistry = apply.PluginRegistry()

func RegisterPlanAction(h pluginapi.PlanHandler) error {
	return planPluginRegistry.RegisterPlan(h)
}

func newDefaultPlanRegistry() *pluginapi.Registry {
	r := pluginapi.NewRegistry()

	for _, h := range builtin.DefaultPlanHandlers() {
		if err := r.RegisterPlan(h); err != nil {
			panic(fmt.Sprintf("register default plan action %q: %v", h.Type, err))
		}
	}

	return r
}

type inspectorAdapter struct {
	inspector.Inspector
}

func (a inspectorAdapter) FirewallAllowedPortsDetailed() ([]pluginapi.FirewallRuleInfo, error) {
	rules, err := a.Inspector.FirewallAllowedPortsDetailed()
	if err != nil {
		return nil, err
	}
	out := make([]pluginapi.FirewallRuleInfo, 0, len(rules))
	for _, r := range rules {
		out = append(out, pluginapi.FirewallRuleInfo{
			Family: r.Family,
			Table:  r.Table,
			Chain:  r.Chain,
			Proto:  r.Proto,
			Port:   r.Port,
			Iif:    r.Iif,
			Oif:    r.Oif,
		})
	}
	return out, nil
}

func planActionContext(insp inspector.Inspector, p *profile.Profile) pluginapi.PlanContext {
	var planInspector pluginapi.PlanInspector
	if insp != nil {
		planInspector = inspectorAdapter{Inspector: insp}
	}
	return pluginapi.PlanContext{
		Inspector: planInspector,
		Profile:   p,
	}
}
