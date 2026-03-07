package plan

import (
	"fmt"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/firewalltemplate"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var planActionRegistry = newDefaultPlanRegistry()

func RegisterPlanAction(h pluginapi.PlanHandler) error {
	return planActionRegistry.Register(h)
}

func newDefaultPlanRegistry() *pluginapi.PlanRegistry {
	r := pluginapi.NewPlanRegistry()

	for _, h := range []pluginapi.PlanHandler{
		packages.PlanHandler(func(ctx pluginapi.PlanContext, spec *profile.PackageSpec) (pluginapi.PlanResult, error) {
			summary, details, noop, err := planPackages(ctx.Inspector, spec)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return pluginapi.PlanResult{Summary: summary, Details: details, Noop: noop}, nil
		}),
		template.PlanHandler(
			func(ctx pluginapi.PlanContext, spec *profile.TemplateSpec) (pluginapi.PlanResult, error) {
				summary, details, err := planTemplate(ctx.Inspector, ctx.Profile, spec)
				if err != nil {
					return pluginapi.PlanResult{}, err
				}
				return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
			},
			func(ctx pluginapi.PlanContext) (pluginapi.PlanResult, error) {
				return planValidateSSHD(ctx.Inspector)
			},
		),
		service.PlanHandler(func(ctx pluginapi.PlanContext, spec *profile.ServiceSpec) (pluginapi.PlanResult, error) {
			summary, details, err := planService(ctx.Inspector, spec)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
		}),
		firewall.PlanHandler(
			func(ctx pluginapi.PlanContext, spec *profile.FirewallSpec) (pluginapi.PlanResult, error) {
				summary, details, err := planFirewall(ctx.Inspector, spec)
				if err != nil {
					return pluginapi.PlanResult{}, err
				}
				return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
			},
			func(ctx pluginapi.PlanContext) (pluginapi.PlanResult, error) {
				return planValidateFirewall(ctx.Inspector)
			},
		),
		firewalltemplate.PlanHandler(func(ctx pluginapi.PlanContext, spec *profile.FirewallTemplateSpec) (pluginapi.PlanResult, error) {
			summary, details, err := planFirewallTemplate(ctx.Inspector, spec)
			if err != nil {
				return pluginapi.PlanResult{}, err
			}
			return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
		}),
	} {
		if err := r.Register(h); err != nil {
			panic(fmt.Sprintf("register default plan action %q: %v", h.Type, err))
		}
	}

	return r
}

func planActionContext(insp inspector.Inspector, p *profile.Profile) pluginapi.PlanContext {
	return pluginapi.PlanContext{
		Inspector: insp,
		Profile:   p,
	}
}
