package executor

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/profile"
)

func Apply(c cli.Command) {
	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}
	sshClient, err := connection.NewSSHClient(*config)
	if err != nil {
		fmt.Printf("unable to connect, %s", err)
	}

	p, err := profile.Load(c.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load profile: %v\n", err)
		os.Exit(1)
	}

	applyProfile(sshClient, p)

}
