package executor

import (
	"log"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func run(client *ssh.Client, cmd string) error {

	log.Printf("remote: %s", cmd)

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = os.Stdout

	session.Stderr = os.Stderr

	return session.Run(cmd)
}

func runRoot(client *ssh.Client, cmd string) error {
	wrapped := "sudo -n sh -lc " + strconv.Quote(cmd)
	return run(client, wrapped)
}
