package executor

import (
	"fmt"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
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

	run(sshClient, "ip addr")

	fmt.Println("Apply")

}
