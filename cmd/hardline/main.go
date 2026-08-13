package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/karvashish/hardline/internals/apply"
	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/plan"
	"github.com/karvashish/hardline/internals/plugins"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
)

var runClock = func() time.Time { return time.Now().UTC() }

func emitRunHeader(subcmd string, c cli.Command) {
	ver, _, err := resolveVerCmd()
	version := "unknown"
	if err == nil {
		version = ver.String()
	}
	parts := []string{
		"# hardline " + subcmd,
		"profile=" + c.Profile,
	}
	if host := strings.TrimSpace(c.Host); host != "" {
		parts = append(parts, "host="+host)
	}
	parts = append(parts,
		"version="+version,
		"time="+runClock().Format("2006-01-02T15:04:05Z"),
	)
	logInfof("%s\n", strings.Join(parts, " "))
}

func emitPhase(name string) {
	logInfof("%s== PHASE: %s ==%s\n", logger.ColorCyan+logger.ColorBold, name, logger.ColorReset)
}

func runVerifyPhase(c cli.Command) (*verify.VerifiedBundle, error) {
	emitPhase("VERIFY")
	bundle, err := runVerify(c)
	if err != nil {
		return nil, err
	}
	logInfof("profile verification passed\n")
	return bundle, nil
}

var (
	parseCmd             = cli.Parse
	showUsage            = cli.Usage
	showCommandUsage     = cli.UsageFor
	runPlan              = plan.Plan
	runPlanNextSteps     = plan.PrintPlanNextSteps
	runApply             = apply.Apply
	runRollback          = rollback.Rollback
	runVerify            = verify.Verify
	setDebugMode         = logger.SetDebug
	useLogFile           = logger.UseLogFile
	resolveVerCmd        = cli.VersionCmd
	loadPlugins          = plugins.LoadFromBinaryDir
	logInfof             = logger.Infof
	logErrorf            = logger.Errorf
	exitFunc             = os.Exit
	installSignalHandler = defaultInstallSignalHandler
)

func defaultInstallSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-ch
		logErrorf("\nreceived %s, initiating graceful shutdown\n", sig)
		cancel()
		sig = <-ch
		logErrorf("\nreceived %s again, forcing exit\n", sig)
		exitFunc(130)
	}()
	return ctx
}

func isHelpArg(arg string) bool {
	switch arg {
	case "-h", "--help", "-help":
		return true
	default:
		return false
	}
}

func main() {
	exitFunc(run(os.Args))
}

func run(args []string) int {
	ctx := installSignalHandler()

	if len(args) < 2 {
		showUsage()
		return 1
	}

	cmd := args[1]

	switch cmd {
	case "-h", "--help", "-help":
		showUsage()
		return 0
	case "plan":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		closeLog, err := useLogFile(c.LogFile)
		if err != nil {
			logErrorf("log file setup failed: %v\n", err)
			return 1
		}
		defer closeLog()
		emitRunHeader("plan", c)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		bundle, err := runVerifyPhase(c)
		if err != nil {
			logErrorf("verify failed: %v\n", err)
			return 1
		}
		emitPhase("PLAN")
		if err := runPlan(c, bundle); err != nil {
			logErrorf("plan failed: %v\n", err)
			return 1
		}
		runPlanNextSteps(c)
		return 0
	case "apply":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		closeLog, err := useLogFile(c.LogFile)
		if err != nil {
			logErrorf("log file setup failed: %v\n", err)
			return 1
		}
		defer closeLog()
		emitRunHeader("apply", c)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		bundle, err := runVerifyPhase(c)
		if err != nil {
			logErrorf("verify failed: %v\n", err)
			return 1
		}
		emitPhase("PLAN")
		if err := runPlan(c, bundle); err != nil {
			logErrorf("plan failed: %v\n", err)
			return 1
		}
		emitPhase("APPLY")
		if err := runApply(ctx, c, bundle); err != nil {
			logErrorf("apply failed: %v\n", err)
			return 1
		}
		return 0
	case "rollback":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		closeLog, err := useLogFile(c.LogFile)
		if err != nil {
			logErrorf("log file setup failed: %v\n", err)
			return 1
		}
		defer closeLog()
		emitRunHeader("rollback", c)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		bundle, err := runVerifyPhase(c)
		if err != nil {
			logErrorf("verify failed: %v\n", err)
			return 1
		}
		emitPhase("ROLLBACK")
		runRollback(c, bundle)
		return 0
	case "verify-profile", "verify", "vp":
		c := parseCmd(cmd, args[2:])
		setDebugMode(c.Debug)
		closeLog, err := useLogFile(c.LogFile)
		if err != nil {
			logErrorf("log file setup failed: %v\n", err)
			return 1
		}
		defer closeLog()
		emitRunHeader("verify-profile", c)
		if err := loadPlugins(); err != nil {
			logErrorf("plugin load failed: %v\n", err)
			return 1
		}
		emitPhase("VERIFY")
		if !c.Debug {
			logInfof("verify-profile %s\n", c.Profile)
		}
		if _, err := runVerify(c); err != nil {
			logErrorf("verify failed: %v\n", err)
			return 1
		}
		logInfof("profile verification passed\n")
		return 0
	case "version", "-v", "-V", "--version", "-version":
		if len(args) > 2 && isHelpArg(args[2]) {
			showCommandUsage("version")
			return 0
		}
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
