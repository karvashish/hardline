package registry

import (
	"fmt"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

var (
	sharedRegistry  = NewDefaultRegistry()
	defaultPlugins  = builtinPlugins
)

func Shared() *pluginapi.Registry {
	return sharedRegistry
}

func builtinPlugins() []pluginapi.Plugin {
	return []pluginapi.Plugin{
		packages.Plugin(),
		template.Plugin(),
		service.Plugin(),
		firewall.Plugin(),
	}
}

func NewDefaultRegistry() *pluginapi.Registry {
	r := pluginapi.NewRegistry()
	for _, p := range defaultPlugins() {
		if err := r.Register(p); err != nil {
			panic(fmt.Sprintf("register default plugin %q: %v", p.Name, err))
		}
	}
	return r
}
