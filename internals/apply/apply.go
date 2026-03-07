package apply

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var (
	newSSHClient    = connection.NewSSHClient
	loadProfile     = profile.Load
	versionCmd      = cli.VersionCmd
	compareSemVer   = cli.CompareSemVer
	runApplyProfile = applyProfile
	runApplyCommand = applyCommand
	exitProcess     = os.Exit
	runStep         = handleStep
)

func Apply(c cli.Command) {
	if err := runApplyCommand(c); err != nil {
		exitProcess(1)
	}
}

func applyCommand(c cli.Command) error {
	if !c.Debug {
		logger.Infof("apply %s\n", c.Profile)
	}

	logger.Debugf("apply: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := newSSHClient(*config)
	if err != nil {
		logger.Errorf("connect failed: %v\n", err)
		return fmt.Errorf("connect failed: %w", err)
	}
	if sshClient != nil {
		defer sshClient.Close()
	}

	logger.Debugf("ssh connection established\n")

	p, err := loadProfile(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		return fmt.Errorf("profile load failed: %w", err)
	}

	logger.Debugf("profile loaded, starting applyProfile\n")

	ver, schemaVer, err := versionCmd()
	if err != nil {
		logger.Errorf("hardline version check failed: %v\n", err)
		return fmt.Errorf("hardline version check failed: %w", err)
	}

	cmp, err := compareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Errorf("invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		return fmt.Errorf("invalid profile.min_hardline value %q: %w", p.MinHardline, err)
	}

	if cmp < 0 {
		logger.Errorf(
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
		return fmt.Errorf(
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf(
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
		return fmt.Errorf(
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
	}

	if err := runApplyProfile(sshClient, p); err != nil {
		logger.Errorf("apply failed: %v\n", err)
		return fmt.Errorf("apply failed: %w", err)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}

	logger.Debugf("apply completed\n")
	return nil
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

			err := runStep(client, p, step)

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
