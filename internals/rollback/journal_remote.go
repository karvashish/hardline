package rollback

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	resolveRemoteStatePath = defaultRemoteStatePath
	runRemoteRoot          = remote.RunRoot
	readRemoteRootFile     = remote.ReadRootFile
	writeRemoteRootFile    = remote.WriteRootFile
	newRemoteSFTPClient    = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
)

func SaveRemoteLast(client *ssh.Client, j *Journal) error {
	if j == nil {
		return fmt.Errorf("journal is nil")
	}

	remotePath := strings.TrimSpace(resolveRemoteStatePath())
	if remotePath == "" {
		return fmt.Errorf("remote rollback state path is empty")
	}

	dir := path.Dir(remotePath)
	if dir != "" && dir != "." {
		if err := runRemoteRoot(client, "mkdir -p "+strconv.Quote(dir)); err != nil {
			return fmt.Errorf("create remote rollback state dir %q: %w", dir, err)
		}
	}

	data, err := marshalJournal(j)
	if err != nil {
		return err
	}

	sftpClient, err := newRemoteSFTPClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := writeRemoteRootFile(client, sftpClient, remotePath, data, 0o600); err != nil {
		return fmt.Errorf("persist remote rollback state %q: %w", remotePath, err)
	}
	return nil
}

func LoadRemoteLast(client *ssh.Client) (*Journal, error) {
	remotePath := strings.TrimSpace(resolveRemoteStatePath())
	if remotePath == "" {
		return nil, fmt.Errorf("remote rollback state path is empty")
	}

	data, err := readRemoteRootFile(client, remotePath)
	if err != nil {
		return nil, fmt.Errorf("read remote rollback state %q: %w", remotePath, err)
	}
	return decodeJournal([]byte(data), remotePath)
}

func defaultRemoteStatePath() string {
	return "/var/lib/hardline/runs/last.json"
}
