package remote

import (
	"bytes"
	"io"
	"os"

	"github.com/karvashish/hardline/pkg/logger"
	"golang.org/x/crypto/ssh"
)

type session interface {
	Run(string) error
	Close() error
	SetWriters(stdout io.Writer, stderr io.Writer)
}

type sshSession struct {
	*ssh.Session
}

func (s sshSession) SetWriters(stdout io.Writer, stderr io.Writer) {
	s.Stdout = stdout
	s.Stderr = stderr
}

var newSession = func(client *ssh.Client) (session, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	return sshSession{Session: sess}, nil
}

var (
	stdoutWriter io.Writer = os.Stdout
	stderrWriter io.Writer = os.Stderr
)

func Run(client *ssh.Client, cmd string) error {
	logger.Debugf("remote cmd: %s\n", cmd)

	session, err := newSession(client)
	if err != nil {
		return err
	}
	defer session.Close()

	if logger.DebugMode() {
		session.SetWriters(stdoutWriter, stderrWriter)
		return session.Run(cmd)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	session.SetWriters(&out, &errb)

	if err := session.Run(cmd); err != nil {
		if errb.Len() > 0 {
			logger.Infof("cmd error: %s\n", errb.String())
		}
		return err
	}

	return nil
}

func RunRoot(client *ssh.Client, cmd string) error {
	wrapped := "sudo -n sh -lc " + shellQuote(cmd)
	return Run(client, wrapped)
}

func RunWithOutput(client *ssh.Client, cmd string) (string, error) {
	logger.Debugf("remote cmd: %s\n", cmd)

	session, err := newSession(client)
	if err != nil {
		return "", err
	}
	defer session.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	session.SetWriters(&out, &errb)

	if err := session.Run(cmd); err != nil {
		if errb.Len() > 0 {
			logger.Infof("cmd error: %s\n", errb.String())
		}
		return out.String(), err
	}

	return out.String(), nil
}

func RunRootWithOutput(client *ssh.Client, cmd string) (string, error) {
	wrapped := "sudo -n sh -lc " + shellQuote(cmd)
	return RunWithOutput(client, wrapped)
}
