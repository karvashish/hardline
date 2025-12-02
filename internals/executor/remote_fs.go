package executor

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/karvashish/hardline/internals/logger"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func writeFile(sftpClient *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
	logger.Debugf("writeFile: path=%q size=%d", remotePath, len(data))

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

	logger.Debugf("writeRootFile: tmp=%q dest=%q", tmpPath, remotePath)

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
	logger.Debugf("readRootFile: path=%q", path)

	cmd := "cat " + path
	wrapped := "sudo -n sh -lc " + strconv.Quote(cmd)

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var out bytes.Buffer
	var errBuf bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errBuf

	if err := session.Run(wrapped); err != nil {
		if errBuf.Len() > 0 {
			logger.Infof("readRootFile error: %s", errBuf.String())
		}
		return "", err
	}
	return out.String(), nil
}
