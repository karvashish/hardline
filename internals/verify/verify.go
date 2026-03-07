package verify

import (
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/pkg/logger"
)

func Verify(c cli.Command) {
	if err := verifyProfile(c); err != nil {
		logger.Errorf("integrity verification failed: %v\n", err)
		os.Exit(1)
	}
}

func verifyProfile(c cli.Command) error {
	if !c.Debug {
		logger.Infof("verify-profile %s\n", c.Profile)
	}

	logger.Debugf("verify-profile: profile=%q\n", c.Profile)

	if err := VerifyProfileIntegrity(c.Profile); err != nil {
		return err
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}
	return nil
}
