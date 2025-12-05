package main

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/apply"
	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/plan"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
)

func main() {
	if len(os.Args) < 2 {
		cli.Usage()
		os.Exit(1)
	}

	cmd := os.Args[1]

	switch cmd {
	case "plan":
		c := cli.Parse(cmd, os.Args[2:])
		logger.SetDebug(c.Debug)
		plan.Plan(c)
	case "apply":
		c := cli.Parse(cmd, os.Args[2:])
		logger.SetDebug(c.Debug)
		apply.Apply(c)
	case "verify-profile", "vp":
		c := cli.Parse(cmd, os.Args[2:])
		logger.SetDebug(c.Debug)
		verify.Verify(c)
	case "version", "-v":
		ver, _, err := cli.VersionCmd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "version check failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("hardline version", ver.String())
		return

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		cli.Usage()
		os.Exit(1)
	}
}
