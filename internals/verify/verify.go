package verify

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
)

var (
	verifyIntegrity     = VerifyProfileIntegrity
	loadVerifyProfile   = profile.Load
	ensureVerifyPlugins = registry.EnsureProfilePlugins
)

func Verify(c cli.Command) {
	if err := verifyProfile(c); err != nil {
		logger.Errorf("verify failed: %v\n", err)
		os.Exit(1)
	}
}

func verifyProfile(c cli.Command) error {
	if !c.Debug {
		logger.Infof("verify-profile %s\n", c.Profile)
	}

	logger.Debugf("verify-profile: profile=%q\n", c.Profile)

	if err := verifyIntegrity(c.Profile); err != nil {
		return err
	}

	p, err := loadVerifyProfile(c.Profile)
	if err != nil {
		return fmt.Errorf("profile load failed: %w", err)
	}

	if err := ensureVerifyPlugins(p); err != nil {
		return fmt.Errorf("required plugin validation failed: %w", err)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}
	return nil
}
