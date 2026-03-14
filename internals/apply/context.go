package apply

import (
	"github.com/karvashish/hardline/internals/runtime"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func applyActionContext(client *ssh.Client, p *profile.Profile) pluginapi.ApplyContext {
	var host pluginapi.Host
	if client != nil {
		host = runtime.NewSSHRuntime(client)
	}
	return pluginapi.ApplyContext{
		Host:    host,
		Profile: p,
	}
}

func applyCaptureContext(client *ssh.Client, p *profile.Profile) pluginapi.CaptureContext {
	var host pluginapi.Host
	if client != nil {
		host = runtime.NewSSHRuntime(client)
	}
	return pluginapi.CaptureContext{
		Host:    host,
		Profile: p,
	}
}
