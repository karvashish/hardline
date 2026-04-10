package apply

import (
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func handleStepWithRegistry(reg *pluginapi.Registry, client *remote.Client, p *profile.Profile, s profile.Step, stepChanges map[string]bool) error {
	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return err
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return err
	}

	return plugin.Apply(remote.BuildContext(client, p, stepChanges), s)
}
