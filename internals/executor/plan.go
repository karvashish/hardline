package executor

import (
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func Plan(c cli.Command) {
	/*
		1. Load and validate a profile (and its actions/templates).
		2. Contact the target server and inspect current state (read-only).
		3. Generate a logical diff of what `apply` would do`.
		4. Compute per-step risk scores and priority order.
		5. Derive mitigations and rollback strategies for each step and use them to reduce risk.
		6. Aggregate a final run-level risk and present it clearly to the user.
	*/
	if !c.Debug {
		logger.Infof("plan %s\n", c.Profile)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	p, err := profile.Load(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting validation\n")

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
		logger.Errorf("hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline)
		os.Exit(1)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf("profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer)
		os.Exit(1)
	}

	if err := p.Affirm(); err != nil {
		logger.Errorf("profile validation failed: %v\n", err)
		os.Exit(1)
	}

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

	if err := planProfile(sshClient, p); err != nil {
		logger.Errorf("plan failed: %v\n", err)
		os.Exit(1)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}

	logger.Debugf("plan completed\n")

	// TODO:
	// 3. Generate diff of what apply would do.
	// 4. Compute per-step risk scores and priority order.
	// 5. Derive mitigations and rollback strategies.
	// 6. Aggregate final run-level risk and print report.
}

func planProfile(client *ssh.Client, p *profile.Profile) error {
	logger.Debugf("planProfile: %d action files\n", len(p.ActionFiles))

	var plans []StepPlan

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				logger.Infof("step: %s (%s)", step.ID, step.Type)
			}
			logger.Debugf("planStep: id=%q type=%q\n", step.ID, step.Type)

			var stop func()
			if !logger.DebugMode() {
				stop = throbber()
			}

			sp, err := planStep(client, step)

			if stop != nil {
				stop()
			}

			if err != nil {
				return err
			}

			plans = append(plans, sp)

			if !logger.DebugMode() {
				logger.Infof("✓\n")
			}
		}
	}

	return nil
}
