package plan

import (
	"github.com/karvashish/hardline/internals/runtime"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func planActionContext(client *ssh.Client, p *profile.Profile) pluginapi.PlanContext {
	var host pluginapi.Host
	if client != nil {
		host = runtime.NewSSHRuntime(client)
	}
	return pluginapi.PlanContext{
		Host:    host,
		Profile: p,
	}
}
