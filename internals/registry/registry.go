package registry

import (
	"fmt"

	"github.com/karvashish/hardline/internals/plugins/filemeta"
	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/packages/apt"
	"github.com/karvashish/hardline/internals/plugins/packages/dnf4"
	"github.com/karvashish/hardline/internals/plugins/packages/dnf5"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

var (
	sharedRegistry = NewDefaultRegistry()
	defaultPlugins = builtinPlugins
)

func Shared() *pluginapi.Registry {
	return sharedRegistry
}

func builtinPlugins() []pluginapi.Plugin {
	return []pluginapi.Plugin{
		apt.Plugin(),
		dnf4.Plugin(),
		dnf5.Plugin(),
		template.Plugin(),
		service.Plugin(),
		firewall.Plugin(),
		filemeta.Plugin(),
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
