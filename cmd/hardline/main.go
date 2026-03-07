package main

import (
	"fmt"
	"io"
	"os"

	"github.com/karvashish/hardline/internals/apply"
	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/plan"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
)

var (
	parseCmd      = cli.Parse
	showUsage     = cli.Usage
	runPlan       = plan.Plan
	runApply      = apply.Apply
	runVerify     = verify.Verify
	setDebugMode  = logger.SetDebug
	resolveVerCmd = cli.VersionCmd
)

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, out io.Writer, errOut io.Writer) int {
	if len(args) < 2 {
		showUsage()
		return 1
	}

	cmd := args[1]

	switch cmd {
	case "plan":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		runPlan(c)
		return 0
	case "apply":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		// Apply must always execute preflight planning/validation first.
		runPlan(c)
		runApply(c)
		return 0
	case "verify-profile", "vp":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		runVerify(c)
		return 0
	case "version", "-v":
		ver, _, err := resolveVerCmd()
		if err != nil {
			fmt.Fprintf(errOut, "version check failed: %v\n", err)
			return 1
		}
		fmt.Fprintf(out, "hardline version %s\n", ver.String())
		return 0
	default:
		fmt.Fprintf(errOut, "unknown command: %s\n", cmd)
		showUsage()
		return 1
	}
}
