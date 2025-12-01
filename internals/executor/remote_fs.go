package executor

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func writeFile(sftpClient *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
	f, err := sftpClient.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(mode)
}

func writeRootFile(client *ssh.Client, sftpClient *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
	tmpPath := fmt.Sprintf("/tmp/.hardline-%d", time.Now().UnixNano())

	if err := writeFile(sftpClient, tmpPath, data, 0600); err != nil {
		return err
	}

	modeOct := strconv.FormatUint(uint64(mode.Perm()), 8)
	cmd := fmt.Sprintf("install -m %s %s %s && rm -f %s", modeOct, tmpPath, remotePath, tmpPath)

	if err := runRoot(client, cmd); err != nil {
		return err
	}
	return nil
}

func readRootFile(client *ssh.Client, path string) (string, error) {
	cmd := "cat " + path
	wrapped := "sudo -n sh -lc " + strconv.Quote(cmd)

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = os.Stderr

	if err := session.Run(wrapped); err != nil {
		return "", err
	}
	return buf.String(), nil
}
