package apply

import (
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func captureStepRecordWithRegistry(reg *pluginapi.Registry, client *remote.Client, p *profile.Profile, s profile.Step) (pluginapi.CaptureResult, error) {
	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return pluginapi.CaptureResult{}, err
	}
	return plugin.Capture(remote.BuildContext(client, p, nil), s)
}
