package apply

import (
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func captureStepRecord(client *ssh.Client, p *profile.Profile, s profile.Step) (pluginapi.StepRecord, error) {
	return captureStepRecordWithRegistry(registry.Shared(), client, p, s)
}

func captureStepRecordWithRegistry(reg *pluginapi.Registry, client *ssh.Client, p *profile.Profile, s profile.Step) (pluginapi.StepRecord, error) {
	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return pluginapi.StepRecord{}, err
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return pluginapi.StepRecord{}, err
	}

	return plugin.Capture(applyCaptureContext(client, p), s)
}
