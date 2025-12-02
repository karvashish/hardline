package main

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/executor"
	"github.com/karvashish/hardline/internals/logger"
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
		executor.Plan(c)
	case "apply":
		c := cli.Parse(cmd, os.Args[2:])
		logger.SetDebug(c.Debug)
		executor.Apply(c)
	case "verify-profile", "vp":
		c := cli.Parse(cmd, os.Args[2:])
		logger.SetDebug(c.Debug)
		executor.Verify(c)
	case "version", "-v":
		cli.VersionCmd()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		cli.Usage()
		os.Exit(1)
	}
}
