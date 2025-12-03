package executor

import (
	"fmt"
	"math"
	"os"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/logger"
	"github.com/karvashish/hardline/internals/profile"
	"golang.org/x/crypto/ssh"
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

func applyProfile(client *ssh.Client, p *profile.Profile) error {
	logger.Debugf("applyProfile: %d action files", len(p.ActionFiles))

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				fmt.Fprintf(os.Stderr, "step: %s (%s) ", step.ID, step.Type)
			}
			logger.Debugf("handleStep: id=%q type=%q", step.ID, step.Type)

			var stop func()
			if !logger.DebugMode() {
				stop = throbber(os.Stderr)
			}

			err := handleStep(client, p, step)

			if stop != nil {
				stop()
			}

			if err != nil {
				return err
			}

			if !logger.DebugMode() {
				fmt.Fprintln(os.Stderr, "✓")
			}
		}
	}
	return nil
}

func throbber(dst *os.File) func() {
	const total = 100
	progress := 0
	stop := make(chan struct{})

	expDelay := func(p int) time.Duration {
		delay := math.Exp((float64(p)/float64(total))*3.0) * 150.0
		return time.Duration(delay) * time.Millisecond
	}

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				if progress >= total {
					progress = 0
				}
				fmt.Fprint(dst, ".")
				progress++
				time.Sleep(expDelay(progress))
			}
		}
	}()

	return func() {
		close(stop)
	}
}
