package apply

import (
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func captureStepRecord(client *ssh.Client, p *profile.Profile, s profile.Step) (rollback.StepRecord, error) {
	plugin, ok := pluginRegistry.Lookup(s.PluginName())
	if !ok {
		return pluginapi.NoopRecord(s, "unknown plugin captured as noop"), nil
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return rollback.StepRecord{}, err
	}

	return plugin.Rollback(applyRollbackContext(client, p), s)
}
