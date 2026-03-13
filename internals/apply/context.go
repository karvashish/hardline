package apply

import (
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func applyActionContext(client *ssh.Client, p *profile.Profile) pluginapi.ApplyContext {
	return pluginapi.ApplyContext{
		Client:  client,
		Profile: p,
	}
}

func applyRollbackContext(client *ssh.Client, p *profile.Profile) pluginapi.RollbackContext {
	return pluginapi.RollbackContext{
		Client:  client,
		Profile: p,
	}
}
