package remote

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
	"golang.org/x/crypto/ssh"
)

// DefaultCmdTimeout is the per-command deadline applied to every remote
// execution. Commands that exceed this duration have their SSH session closed,
// causing the run to return a timeout error. Override in tests as needed.
var DefaultCmdTimeout = 5 * time.Minute

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

func (c *Client) Run(cmd string) error {
	_, err := c.run(cmd, DefaultCmdTimeout)
	return err
}

func (c *Client) RunRoot(cmd string) error {
	_, err := c.run("sudo -n sh -lc "+shellQuote(cmd), DefaultCmdTimeout)
	return err
}

func (c *Client) RunWithOutput(cmd string) (string, error) {
	return c.run(cmd, DefaultCmdTimeout)
}

func (c *Client) RunRootWithOutput(cmd string) (string, error) {
	return c.run("sudo -n sh -lc "+shellQuote(cmd), DefaultCmdTimeout)
}

func (c *Client) RunRootWithTimeout(cmd string, timeout time.Duration) (string, error) {
	return c.run("sudo -n sh -lc "+shellQuote(cmd), timeout)
}

func (c *Client) run(cmd string, timeout time.Duration) (string, error) {
	logger.Debugf("remote cmd: %s\n", cmd)

	sess, err := newSession(c.ssh)
	if err != nil {
		return "", err
	}
	defer sess.Close()

	var out bytes.Buffer
	var errb bytes.Buffer
	sess.SetWriters(&out, &errb)

	timedOut := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		close(timedOut)
		sess.Close()
	})
	defer timer.Stop()

	if err := sess.Run(cmd); err != nil {
		select {
		case <-timedOut:
			return "", fmt.Errorf("remote command timed out after %s", timeout)
		default:
		}
		if errb.Len() > 0 {
			logger.Infof("cmd error: %s\n", errb.String())
		}
		return out.String(), err
	}

	return out.String(), nil
}
