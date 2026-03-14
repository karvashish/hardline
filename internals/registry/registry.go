package registry

import (
	"fmt"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var sharedRegistry = NewDefaultRegistry()

func Shared() *pluginapi.Registry {
	return sharedRegistry
}

func EnsureProfilePlugins(p *profile.Profile) error {
	return pluginapi.EnsureProfilePlugins(Shared(), p)
}

func NewDefaultRegistry() *pluginapi.Registry {
	return newDefaultRegistry(func(r *pluginapi.Registry, plugin pluginapi.Plugin) error {
		return r.Register(plugin)
	})
}

func newDefaultRegistry(register func(*pluginapi.Registry, pluginapi.Plugin) error) *pluginapi.Registry {
	r := pluginapi.NewRegistry()

	registerDefaultPlugin(r, register, packages.Plugin())
	registerDefaultPlugin(r, register, template.Plugin())
	registerDefaultPlugin(r, register, service.Plugin())
	registerDefaultPlugin(r, register, firewall.Plugin())

	return r
}

func registerDefaultPlugin(r *pluginapi.Registry, register func(*pluginapi.Registry, pluginapi.Plugin) error, plugin pluginapi.Plugin) {
	if err := register(r, plugin); err != nil {
		panic(fmt.Sprintf("register default plugin %q: %v", plugin.Name, err))
	}
}
