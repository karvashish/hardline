package executor

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/logger"
	"github.com/karvashish/hardline/internals/profile"
)

func Apply(c cli.Command) {
	if !c.Debug {
		fmt.Fprintf(os.Stderr, "apply %s\n", c.Profile)
	}

	logger.Debugf("apply: profile=%q host=%q user=%q key=%q", c.Profile, c.Host, c.User, c.KeyPath)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := connection.NewSSHClient(*config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
		os.Exit(1)
	}
	defer sshClient.Close()

	logger.Debugf("ssh connection established")

	p, err := profile.Load(c.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profile load failed: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting applyProfile")

	if err := applyProfile(sshClient, p); err != nil {
		fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
		os.Exit(1)
	}

	if !c.Debug {
		fmt.Fprintln(os.Stderr, "ok")
	}

	logger.Debugf("apply completed")
}
