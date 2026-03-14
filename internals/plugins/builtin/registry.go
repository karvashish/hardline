package builtin

import (
	"os"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/internals/plugins/service"
	"github.com/karvashish/hardline/internals/plugins/template"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ApplyDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
	NewSFTPClient     func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile     func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

func DefaultPlugins(applyDeps ApplyDeps, rollbackDeps RollbackDeps) []pluginapi.Plugin {
	return []pluginapi.Plugin{
		packages.Plugin(packages.ApplyDeps{
			RunRoot: applyDeps.RunRoot,
		}, packages.RollbackDeps{
			RunRootWithOutput: rollbackDeps.RunRootWithOutput,
		}),
		template.Plugin(template.ApplyDeps{
			RunRoot:           applyDeps.RunRoot,
			RunRootWithOutput: applyDeps.RunRootWithOutput,
			ReadRootFile:      applyDeps.ReadRootFile,
			NewSFTPClient:     applyDeps.NewSFTPClient,
			WriteRootFile:     applyDeps.WriteRootFile,
		}, template.RollbackDeps{
			RunRoot:           rollbackDeps.RunRoot,
			RunRootWithOutput: rollbackDeps.RunRootWithOutput,
			ReadRootFile:      rollbackDeps.ReadRootFile,
		}),
		service.Plugin(service.ApplyDeps{
			RunRoot: applyDeps.RunRoot,
		}, service.RollbackDeps{
			RunRootWithOutput: rollbackDeps.RunRootWithOutput,
		}),
		firewall.Plugin(firewall.ApplyDeps{
			RunRoot:           applyDeps.RunRoot,
			RunRootWithOutput: applyDeps.RunRootWithOutput,
			ReadRootFile:      applyDeps.ReadRootFile,
			NewSFTPClient:     applyDeps.NewSFTPClient,
			WriteRootFile:     applyDeps.WriteRootFile,
		}, firewall.RollbackDeps{
			RunRoot:           rollbackDeps.RunRoot,
			RunRootWithOutput: rollbackDeps.RunRootWithOutput,
			ReadRootFile:      rollbackDeps.ReadRootFile,
		}),
	}
}

func DefaultBundle(applyDeps ApplyDeps, rollbackDeps RollbackDeps) pluginapi.PluginBundle {
	return pluginapi.PluginBundle{
		Name:    "builtin",
		Plugins: DefaultPlugins(applyDeps, rollbackDeps),
	}
}
