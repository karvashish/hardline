package apply

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/firewalltemplate"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var applyActionRegistry = newDefaultApplyRegistry()

func RegisterApplyAction(h pluginapi.ApplyHandler) error {
	return applyActionRegistry.Register(h)
}

func newDefaultApplyRegistry() *pluginapi.ApplyRegistry {
	r := pluginapi.NewApplyRegistry()

	for _, h := range []pluginapi.ApplyHandler{
		packages.ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.PackageSpec) error {
			return handlePackages(ctx.Client, spec)
		}),
		template.ApplyHandler(
			func(ctx pluginapi.ApplyContext, spec *profile.TemplateSpec) error {
				return handleTemplate(ctx.Client, ctx.Profile, spec)
			},
			func(ctx pluginapi.ApplyContext) error {
				return validateSSHD(ctx.Client)
			},
		),
		service.ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.ServiceSpec) error {
			return handleService(ctx.Client, spec)
		}),
		firewall.ApplyHandler(
			func(ctx pluginapi.ApplyContext, spec *profile.FirewallSpec) error {
				return handleFirewall(ctx.Client, spec)
			},
			func(ctx pluginapi.ApplyContext) error {
				return validateFirewall(ctx.Client)
			},
		),
		firewalltemplate.ApplyHandler(func(ctx pluginapi.ApplyContext, spec *profile.FirewallTemplateSpec) error {
			return handleFirewallTemplate(ctx.Client, ctx.Profile, spec)
		}),
	} {
		if err := r.Register(h); err != nil {
			panic(fmt.Sprintf("register default apply action %q: %v", h.Type, err))
		}
	}

	return r
}

func applyActionContext(client *ssh.Client, p *profile.Profile) pluginapi.ApplyContext {
	return pluginapi.ApplyContext{
		Client:  client,
		Profile: p,
	}
}

func applyValidateByKind(client *ssh.Client, p *profile.Profile, kind string) error {
	validateFn, ok := applyActionRegistry.LookupValidate(kind)
	if !ok {
		return fmt.Errorf("unsupported validate kind %q", strings.TrimSpace(kind))
	}
	return validateFn(applyActionContext(client, p))
}
