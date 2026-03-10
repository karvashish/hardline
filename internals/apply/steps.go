package apply

import (
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
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
	pluginName := s.PluginName()

	plugin, ok := pluginRegistry.Lookup(pluginName)
	if !ok {
		logger.Warnf("warning: empty or unknown plugin %q (id=%q)\n", s.Plugin, s.ID)
		return nil
	}
	if err := pluginapi.EnsureValidationPolicy(s, plugin); err != nil {
		return err
	}

	return plugin.Apply(applyActionContext(client, p), s)
}
