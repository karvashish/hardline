package apply

import (
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func Apply(c cli.Command) {
	if !c.Debug {
		logger.Infof("apply %s\n", c.Profile)
	}

	logger.Debugf("apply: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := connection.NewSSHClient(*config)
	if err != nil {
		logger.Errorf("connect failed: %v\n", err)
		os.Exit(1)
	}
	defer sshClient.Close()

	logger.Debugf("ssh connection established\n")

	p, err := profile.Load(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting applyProfile\n")

	ver, schemaVer, err := cli.VersionCmd()
	if err != nil {
		logger.Errorf("hardline version check failed: %v\n", err)
		os.Exit(1)
	}

	cmp, err := cli.CompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Errorf("invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		os.Exit(1)
	}

	if cmp < 0 {
		logger.Errorf(
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
		os.Exit(1)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf(
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
		os.Exit(1)
	}

	if err := applyProfile(sshClient, p); err != nil {
		logger.Errorf("apply failed: %v\n", err)
		os.Exit(1)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}

	logger.Debugf("apply completed\n")
}

func applyProfile(client *ssh.Client, p *profile.Profile) error {
	logger.Debugf("applyProfile: %d action files\n", len(p.ActionFiles))

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				logger.Infof("step: %s (%s) ", step.ID, step.Type)
			}
			logger.Debugf("handleStep: id=%q type=%q\n", step.ID, step.Type)

			var stop func()
			if !logger.DebugMode() {
				stop = utils.Throbber()
			}

			err := handleStep(client, p, step)

			if stop != nil {
				stop()
			}

			if err != nil {
				return err
			}

			if !logger.DebugMode() {
				logger.Infof("✓\n")
			}
		}
	}
	return nil
}
