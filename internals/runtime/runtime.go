package runtime

import (
	"os"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sftpStatClient interface {
	Stat(string) (os.FileInfo, error)
	Close() error
}

var (
	runRoot           = remote.RunRoot
	runRootWithOutput = remote.RunRootWithOutput
	readRootFile      = remote.ReadRootFile
	newSFTPClient     = func(client *ssh.Client) (sftpStatClient, error) { return sftp.NewClient(client) }
)

type SSHRuntime struct {
	client *ssh.Client
}

func NewSSHRuntime(client *ssh.Client) *SSHRuntime {
	return &SSHRuntime{client: client}
}

func (r *SSHRuntime) RunRoot(cmd string) error {
	return runRoot(r.client, cmd)
}

func (r *SSHRuntime) RunRootWithOutput(cmd string) (string, error) {
	return runRootWithOutput(r.client, cmd)
}

func (r *SSHRuntime) Stat(path string) (os.FileInfo, error) {
	sftpClient, err := newSFTPClient(r.client)
	if err != nil {
		return nil, err
	}
	defer sftpClient.Close()

	return sftpClient.Stat(path)
}

func (r *SSHRuntime) ReadRootFile(path string) (string, error) {
	return readRootFile(r.client, path)
}
