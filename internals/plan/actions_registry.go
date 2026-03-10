package plan

import (
	"fmt"

	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/internals/runtime"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var planPluginRegistry = newDefaultPlanRegistry()

func RegisterPlugin(p pluginapi.Plugin) error {
	return planPluginRegistry.Register(p)
}

func newDefaultPlanRegistry() *pluginapi.Registry {
	r := pluginapi.NewRegistry()

	bundle := builtin.DefaultBundle(
		builtin.ApplyDeps{},
		builtin.RollbackDeps{},
	)
	if err := r.RegisterBundle(bundle); err != nil {
		panic(fmt.Sprintf("register default plugin bundle %q: %v", bundle.Name, err))
	}

	return r
}

func planActionContext(client *ssh.Client, p *profile.Profile) pluginapi.PlanContext {
	var hostRuntime pluginapi.Runtime
	if client != nil {
		hostRuntime = runtime.NewSSHRuntime(client)
	}
	return pluginapi.PlanContext{
		Runtime: hostRuntime,
		Profile: p,
	}
}
