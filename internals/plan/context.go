package plan

import (
	"github.com/karvashish/hardline/internals/runtime"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func planActionContext(client *ssh.Client, p *profile.Profile) pluginapi.PlanContext {
	var hostRuntime pluginapi.Runtime
	if client != nil {
		hostRuntime = runtime.NewSSHRuntime(client)
	}
	return pluginapi.PlanContext{
		Runtime: hostRuntime,
		Profile: p,
	}
}
