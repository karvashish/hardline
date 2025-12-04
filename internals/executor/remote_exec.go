package executor

import (
	"bytes"
	"os"
	"strconv"

	"github.com/karvashish/hardline/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func run(client *ssh.Client, cmd string) error {
	logger.Debugf("remote cmd: %s", cmd)

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if logger.DebugMode() {
		session.Stdout = os.Stdout
		session.Stderr = os.Stderr
		return session.Run(cmd)
	}

	var out bytes.Buffer
	var errb bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errb

	if err := session.Run(cmd); err != nil {
		if errb.Len() > 0 {
			logger.Infof("cmd error: %s", errb.String())
		}
		return err
	}

	return nil
}

func runRoot(client *ssh.Client, cmd string) error {
	wrapped := "sudo -n sh -lc " + strconv.Quote(cmd)
	return run(client, wrapped)
}
