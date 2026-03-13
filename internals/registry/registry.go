package registry

import (
	"fmt"

	"github.com/karvashish/hardline/internals/plugins/builtin"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	runRootCmd           = remote.RunRoot
	runRootCmdWithOutput = remote.RunRootWithOutput
	readRootFile         = remote.ReadRootFile
	writeRootFile        = remote.WriteRootFile
)

var sharedRegistry = NewDefaultRegistry()

func Shared() *pluginapi.Registry {
	return sharedRegistry
}

func newRegistrySFTPClient(client *ssh.Client) (*sftp.Client, error) {
	return sftp.NewClient(client)
}

func NewDefaultRegistry() *pluginapi.Registry {
	return newDefaultRegistry(func(r *pluginapi.Registry, bundle pluginapi.PluginBundle) error {
		return r.RegisterBundle(bundle)
	})
}

func newDefaultRegistry(register func(*pluginapi.Registry, pluginapi.PluginBundle) error) *pluginapi.Registry {
	r := pluginapi.NewRegistry()

	bundle := builtin.DefaultBundle(
		builtin.ApplyDeps{
			RunRoot:       runRootCmd,
			NewSFTPClient: newRegistrySFTPClient,
			WriteRootFile: writeRootFile,
		},
		builtin.RollbackDeps{
			RunRoot:           runRootCmd,
			RunRootWithOutput: runRootCmdWithOutput,
			ReadRootFile:      readRootFile,
		},
	)
	if err := register(r, bundle); err != nil {
		panic(fmt.Sprintf("register default plugin bundle %q: %v", bundle.Name, err))
	}

	return r
}
