package remote

import (
	"os"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpStatClient interface {
	Stat(string) (os.FileInfo, error)
	Close() error
}

var (
	newSFTPClient = func(client *ssh.Client) (sftpStatClient, error) { return sftp.NewClient(client) }
	newSFTPWriter = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
)

// Client is the one remote-execution surface. It wraps an SSH connection and
// exposes every operation the rest of the codebase performs against the
// remote host. It also satisfies pluginapi.Host so it can be handed directly
// to plugins via BuildContext.
type Client struct {
	ssh *ssh.Client
}

func New(sshClient *ssh.Client) *Client {
	return &Client{ssh: sshClient}
}

func (c *Client) Close() error {
	if c == nil || c.ssh == nil {
		return nil
	}
	return c.ssh.Close()
}

func (c *Client) Stat(path string) (os.FileInfo, error) {
	sftpClient, err := newSFTPClient(c.ssh)
	if err != nil {
		return nil, err
	}
	defer sftpClient.Close()

	return sftpClient.Stat(path)
}

func BuildContext(c *Client, p *profile.Profile, stepChanges map[string]bool) pluginapi.Context {
	var host pluginapi.Host
	if c != nil && c.ssh != nil {
		host = c
	}
	return pluginapi.Context{
		Host:        host,
		Profile:     p,
		Overrides:   p.RuntimeOverrides(),
		StepChanges: stepChanges,
	}
}
