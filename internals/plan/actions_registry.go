package plan

import (
	"fmt"

	"github.com/karvashish/hardline/internals/inspector"
	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var planActionRegistry = newDefaultPlanRegistry()

func RegisterPlanAction(h pluginapi.PlanHandler) error {
	return planActionRegistry.Register(h)
}

func newDefaultPlanRegistry() *pluginapi.PlanRegistry {
	r := pluginapi.NewPlanRegistry()

	for _, h := range builtin.DefaultPlanHandlers() {
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
