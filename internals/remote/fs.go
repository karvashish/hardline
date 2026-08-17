package remote

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
)

var (
	writeFileFn        = writeFile
	generateTempSuffix = defaultGenerateTempSuffix
	cryptoRandRead     = rand.Read
)

type remoteFile interface {
	Write([]byte) (int, error)
	Close() error
	Chmod(os.FileMode) error
}

func defaultGenerateTempSuffix() (string, error) {
	var b [8]byte
	if _, err := cryptoRandRead(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func writeFile(sftpClient *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
	return writeFileWithOpener(sftpClient, remotePath, data, mode, func(client *sftp.Client, path string) (remoteFile, error) {
		return client.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	})
}

func writeFileWithOpener(
	sftpClient *sftp.Client,
	remotePath string,
	data []byte,
	mode os.FileMode,
	open func(*sftp.Client, string) (remoteFile, error),
) error {
	logger.Debugf("writeFile: path=%q size=%d\n", remotePath, len(data))

	f, err := open(sftpClient, remotePath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Chmod(mode)
}

func (c *Client) ReadRootFile(path string) (string, error) {
	logger.Debugf("readRootFile: path=%q\n", path)
	return c.RunRootWithOutput("cat " + shellQuote(path))
}

func (c *Client) WriteRootFile(remotePath string, data []byte, mode os.FileMode) error {
	suffix, err := generateTempSuffix()
	if err != nil {
		return fmt.Errorf("generate temp path: %w", err)
	}
	tmpPath := "/tmp/.hardline-" + suffix

	logger.Debugf("writeRootFile: tmp=%q dest=%q\n", tmpPath, remotePath)

	sftpClient, err := newSFTPWriter(c.ssh)
	if err != nil {
		return err
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := writeFileFn(sftpClient, tmpPath, data, 0600); err != nil {
		return err
	}

	modeOct := pluginapi.FormatFileMode(mode)
	quotedTmp := shellQuote(tmpPath)
	cmd := fmt.Sprintf("install -m %s -- %s %s && rm -f -- %s", modeOct, quotedTmp, shellQuote(remotePath), quotedTmp)

	return c.RunRoot(cmd)
}
