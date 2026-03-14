package main

import (
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var HardlinePluginV1 = pluginapi.PluginBundle{
	Name: "firewall_template",
	Plugins: []pluginapi.Plugin{
		Plugin(
			ApplyDeps{
				RunRoot:           remote.RunRoot,
				RunRootWithOutput: remote.RunRootWithOutput,
				ReadRootFile:      remote.ReadRootFile,
				NewSFTPClient:     newPluginSFTPClient,
				WriteRootFile:     remote.WriteRootFile,
			},
			RollbackDeps{
				RunRoot:           remote.RunRoot,
				RunRootWithOutput: remote.RunRootWithOutput,
				ReadRootFile:      remote.ReadRootFile,
			},
		),
	},
}

func newPluginSFTPClient(client *ssh.Client) (*sftp.Client, error) {
	return sftp.NewClient(client)
}
