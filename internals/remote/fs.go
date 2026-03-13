package remote

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type fileSession interface {
	Run(string) error
	Close() error
	SetWriters(stdout io.Writer, stderr io.Writer)
}

type sshFileSession struct {
	*ssh.Session
}

func (s sshFileSession) SetWriters(stdout io.Writer, stderr io.Writer) {
	s.Stdout = stdout
	s.Stderr = stderr
}

var newFileSession = newSSHFileSession

func newSSHFileSession(client *ssh.Client) (fileSession, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return sshFileSession{Session: sess}, nil
}

var (
	writeFileFn = writeFile
	runRootFn   = RunRoot
	nowUnixNano = currentUnixNano
)

type remoteFile interface {
	Write([]byte) (int, error)
	Close() error
	Chmod(os.FileMode) error
}

func currentUnixNano() int64 {
	return time.Now().UnixNano()
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

func WriteRootFile(client *ssh.Client, sftpClient *sftp.Client, remotePath string, data []byte, mode os.FileMode) error {
	tmpPath := fmt.Sprintf("/tmp/.hardline-%d", nowUnixNano())

	logger.Debugf("writeRootFile: tmp=%q dest=%q\n", tmpPath, remotePath)

	if err := writeFileFn(sftpClient, tmpPath, data, 0600); err != nil {
		return err
	}

	modeOct := strconv.FormatUint(uint64(mode.Perm()), 8)
	cmd := fmt.Sprintf("install -m %s %s %s && rm -f %s", modeOct, tmpPath, remotePath, tmpPath)

	if err := runRootFn(client, cmd); err != nil {
		return err
	}
	return nil
}

func ReadRootFile(client *ssh.Client, path string) (string, error) {
	logger.Debugf("readRootFile: path=%q\n", path)

	cmd := "cat " + path
	wrapped := "sudo -n sh -lc " + strconv.Quote(cmd)

	session, err := newFileSession(client)
	if err != nil {
		return "", err
	}
	defer session.Close()

	var out bytes.Buffer
	var errBuf bytes.Buffer
	session.SetWriters(&out, &errBuf)

	if err := session.Run(wrapped); err != nil {
		if errBuf.Len() > 0 {
			logger.Infof("readRootFile error: %s\n", errBuf.String())
		}
		return "", err
	}
	return out.String(), nil
}
