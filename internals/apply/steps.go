package apply

import (
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	runRootCmd           = remote.RunRoot
	runRootCmdWithOutput = remote.RunRootWithOutput
	readRootFile         = remote.ReadRootFile
	newSFTPClient        = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
	writeRootFile        = remote.WriteRootFile
)

func resetApplyStepState() {}

func handleStep(client *ssh.Client, p *profile.Profile, s profile.Step) error {
	return handleStepWithRegistry(registry.Shared(), client, p, s)
}

func handleStepWithRegistry(reg *pluginapi.Registry, client *ssh.Client, p *profile.Profile, s profile.Step) error {
	plugin, err := pluginapi.RequireStepPlugin(reg, s)
	if err != nil {
		return err
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return err
	}

	return plugin.Apply(applyActionContext(client, p), s)
}
