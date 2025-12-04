package executor

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
)

func Plan(c cli.Command) {
	/*
		1. Load and validate a profile (and its actions/templates).
		2. Contact the target server and inspect current state (read-only).
		3. Generate a logical diff of what `apply` would do.
		4. Compute per-step risk scores and priority order.
		5. Derive mitigations and rollback strategies for each step and use them to reduce risk.
		6. Aggregate a final run-level risk and present it clearly to the user.
	*/
	if !c.Debug {
		fmt.Fprintf(os.Stderr, "plan %s\n", c.Profile)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q", c.Profile, c.Host, c.User, c.KeyPath)

	p, err := profile.Load(c.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profile load failed: %v\n", err)
		os.Exit(1)
	}

	logger.Debugf("profile loaded, starting validation")

	ver, schemaVer, err := cli.VersionCmd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hardline version check failed: %v\n", err)
		os.Exit(1)
	}

	cmp, err := cli.CompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		os.Exit(1)
	}

	if cmp < 0 {
		fmt.Fprintf(os.Stderr,
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
		os.Exit(1)
	}

	if p.ProfileSchema > schemaVer {
		fmt.Fprintf(os.Stderr,
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
		os.Exit(1)
	}

	if err := p.Affirm(); err != nil {
		fmt.Fprintf(os.Stderr, "profile validation failed: %v\n", err)
		os.Exit(1)
	}

	// config := &connection.Config{
	// 	User:    c.User,
	// 	KeyPath: c.KeyPath,
	// 	Host:    c.Host,
	// }

	// sshClient, err := connection.NewSSHClient(*config)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "connect failed: %v\n", err)
	// 	os.Exit(1)
	// }
	// defer sshClient.Close()

	// logger.Debugf("ssh connection established")

	// TODO:
	// 2. Inspect current state (read-only).
	// 3. Generate diff of what apply would do.
	// 4. Compute per-step risk scores and priority order.
	// 5. Derive mitigations and rollback strategies.
	// 6. Aggregate final run-level risk and print report.
}
