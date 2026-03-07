package main

import (
	"os"

	"github.com/karvashish/hardline/internals/apply"
	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/plan"
	"github.com/karvashish/hardline/internals/plugins"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
)

var (
	parseCmd      = cli.Parse
	showUsage     = cli.Usage
	runPlan       = plan.Plan
	runApply      = apply.Apply
	runRollback   = rollback.Rollback
	runVerify     = verify.Verify
	setDebugMode  = logger.SetDebug
	resolveVerCmd = cli.VersionCmd
	loadPlugins   = plugins.LoadFromBinaryDir
	logInfof      = logger.Infof
	logErrorf     = logger.Errorf
)

func main() {
	os.Exit(run(os.Args))
}

func run(args []string) int {
	if len(args) < 2 {
		showUsage()
		return 1
	}

	cmd := args[1]

	switch cmd {
	case "plan":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		runPlan(c)
		return 0
	case "apply":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		// Apply must always execute preflight planning/validation first.
		runPlan(c)
		runApply(c)
		return 0
	case "rollback":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		runRollback(c)
		return 0
	case "verify-profile", "vp":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		runVerify(c)
		return 0
	case "version", "-v":
		ver, _, err := resolveVerCmd()
		if err != nil {
			logErrorf("version check failed: %v\n", err)
			return 1
		}
		logInfof("hardline version %s\n", ver.String())
		return 0
	default:
		logErrorf("unknown command: %s\n", cmd)
		showUsage()
		return 1
	}
}
