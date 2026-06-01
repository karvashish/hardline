package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/cli"
)

func TestRun_NoArgs_ShowsUsage(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }

	code := run([]string{"hardline"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
}

func TestRun_HelpFlag_ShowsUsage(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }
	parseCmd = func(string, []string) cli.Command {
		t.Fatal("parse should not be called for -h")
		return cli.Command{}
	}

	code := run([]string{"hardline", "-h"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
}

func TestRun_DoubleDashHelp_ShowsUsage(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }
	parseCmd = func(string, []string) cli.Command {
		t.Fatal("parse should not be called for --help")
		return cli.Command{}
	}

	code := run([]string{"hardline", "--help"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
}

func TestRun_DashHelp_ShowsUsage(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }
	parseCmd = func(string, []string) cli.Command {
		t.Fatal("parse should not be called for -help")
		return cli.Command{}
	}

	code := run([]string{"hardline", "-help"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
}

func TestIsHelpArgFalse(t *testing.T) {
	if isHelpArg("nope") {
		t.Fatal("expected non-help arg to return false")
	}
}

func TestRun_HelpCommand_IsUnknown(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "help"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
	if got := errOut.String(); got == "" || !bytes.Contains([]byte(got), []byte("unknown command: help")) {
		t.Fatalf("expected unknown command message, got %q", got)
	}
}

func TestRun_UnknownCommand_ShowsUsage(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var usageCalls int
	showUsage = func() { usageCalls++ }
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "nope"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
	if got := errOut.String(); got == "" || !bytes.Contains([]byte(got), []byte("unknown command: nope")) {
		t.Fatalf("expected unknown command message, got %q", got)
	}
}

func TestRun_PlanDispatch(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	var parseName string
	parseCmd = func(command string, args []string) cli.Command {
		parseName = command
		return cli.Command{
			Name:          command,
			Profile:       "p",
			Debug:         true,
			OverridesFile: "overrides.json",
		}
	}

	var debugSet bool
	setDebugMode = func(debug bool) { debugSet = debug }
	var logFilePath string
	useLogFile = func(path string) (func(), error) {
		logFilePath = path
		return func() {}, nil
	}
	loadPlugins = func() error { return nil }

	var verifyCalled, planCalled, nextStepsCalled bool
	runVerify = func(cli.Command) error {
		verifyCalled = true
		return nil
	}
	runPlan = func(c cli.Command) error {
		if c.Name != "plan" {
			t.Fatalf("unexpected command passed to plan: %+v", c)
		}
		planCalled = true
		return nil
	}
	runPlanNextSteps = func(c cli.Command) {
		nextStepsCalled = true
		if c.Profile != "p" || c.Host != "" || c.OverridesFile != "overrides.json" {
			t.Fatalf("unexpected next-step args: %+v", c)
		}
	}
	runApply = func(context.Context, cli.Command) error {
		t.Fatal("apply handler should not be called for plan command")
		return nil
	}
	runRollback = func(cli.Command) { t.Fatal("rollback handler should not be called for plan command") }

	code := run([]string{"hardline", "plan", "profile"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if parseName != "plan" {
		t.Fatalf("expected parse command plan, got %q", parseName)
	}
	if !debugSet {
		t.Fatal("expected debug mode to be set from parsed command")
	}
	if logFilePath != "" {
		t.Fatalf("did not expect log file setup for empty path, got %q", logFilePath)
	}
	if !verifyCalled {
		t.Fatal("expected verify to run before plan")
	}
	if !planCalled {
		t.Fatal("expected plan handler to be called")
	}
	if !nextStepsCalled {
		t.Fatal("expected plan next steps to be printed for standalone plan")
	}
}

func TestRun_ApplyRunsPlanThenApply(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p", LogFile: "/tmp/hardline.log"}
	}
	setDebugMode = func(bool) {}
	var logFilePath string
	useLogFile = func(path string) (func(), error) {
		logFilePath = path
		return func() {}, nil
	}
	loadPlugins = func() error { return nil }

	var order []string
	runVerify = func(cli.Command) error {
		order = append(order, "verify")
		return nil
	}
	runPlan = func(cli.Command) error {
		order = append(order, "plan")
		return nil
	}
	runPlanNextSteps = func(cli.Command) {
		t.Fatal("plan next steps should not be printed during apply")
	}
	runApply = func(context.Context, cli.Command) error {
		order = append(order, "apply")
		return nil
	}
	runRollback = func(cli.Command) { t.Fatal("rollback handler should not be called for apply command") }

	code := run([]string{"hardline", "apply", "profile"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if len(order) != 3 || order[0] != "verify" || order[1] != "plan" || order[2] != "apply" {
		t.Fatalf("expected order [verify plan apply], got %#v", order)
	}
	if logFilePath != "/tmp/hardline.log" {
		t.Fatalf("expected log file path to be forwarded, got %q", logFilePath)
	}
}

func TestRun_VerifyDispatch(t *testing.T) {
	for _, alias := range []string{"verify", "vp"} {
		t.Run(alias, func(t *testing.T) {
			restore := stubHandlers()
			defer restore()

			parseCmd = func(command string, args []string) cli.Command {
				return cli.Command{Name: command, Profile: "p", LogFile: "/tmp/verify.log"}
			}
			setDebugMode = func(bool) {}
			var logFilePath string
			useLogFile = func(path string) (func(), error) {
				logFilePath = path
				return func() {}, nil
			}
			loadPlugins = func() error { return nil }

			var verifyCalls int
			runVerify = func(c cli.Command) error {
				verifyCalls++
				if c.Name != alias {
					t.Fatalf("expected verify alias name %q, got %q", alias, c.Name)
				}
				return nil
			}

			code := run([]string{"hardline", alias, "profile"})
			if code != 0 {
				t.Fatalf("expected exit code 0, got %d", code)
			}
			if verifyCalls != 1 {
				t.Fatalf("expected verify call once, got %d", verifyCalls)
			}
			if logFilePath != "/tmp/verify.log" {
				t.Fatalf("expected verify log file path to be forwarded, got %q", logFilePath)
			}
		})
	}
}

func TestRun_VerifyProfileDispatch_PrintsStatus(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }
	runVerify = func(c cli.Command) error {
		if c.Name != "verify-profile" {
			t.Fatalf("expected verify-profile command name, got %q", c.Name)
		}
		return nil
	}

	var out bytes.Buffer
	logInfof = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format, args...)
	}

	code := run([]string{"hardline", "verify-profile", "profile"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if got := out.String(); !bytes.Contains([]byte(got), []byte("verify-profile p")) || !bytes.Contains([]byte(got), []byte("profile verification passed")) {
		t.Fatalf("expected verify-profile status output, got %q", got)
	}
}

func TestRun_VerifyPluginLoadFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	loadPlugins = func() error { return fmt.Errorf("bad plugin") }

	var verifyCalled bool
	runVerify = func(cli.Command) error {
		verifyCalled = true
		return nil
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "verify-profile", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if verifyCalled {
		t.Fatal("verify handler should not run when plugin loading fails")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("plugin load failed: bad plugin")) {
		t.Fatalf("expected plugin load error output, got %q", got)
	}
}

func TestRun_RollbackDispatch(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "starter-secure-ubuntu-24.04-lts", LogFile: "/tmp/rollback.log"}
	}
	setDebugMode = func(bool) {}
	var logFilePath string
	useLogFile = func(path string) (func(), error) {
		logFilePath = path
		return func() {}, nil
	}
	loadPlugins = func() error { return nil }

	var verifyCalled bool
	runVerify = func(cli.Command) error {
		verifyCalled = true
		return nil
	}

	var rollbackCalls int
	runRollback = func(c cli.Command) {
		rollbackCalls++
		if c.Name != "rollback" {
			t.Fatalf("expected rollback command name, got %q", c.Name)
		}
	}
	runPlan = func(cli.Command) error { t.Fatal("plan handler should not be called for rollback command"); return nil }
	runApply = func(context.Context, cli.Command) error {
		t.Fatal("apply handler should not be called for rollback command")
		return nil
	}

	code := run([]string{"hardline", "rollback", "starter-secure-ubuntu-24.04-lts"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if !verifyCalled {
		t.Fatal("expected verify to run before rollback")
	}
	if rollbackCalls != 1 {
		t.Fatalf("expected rollback call once, got %d", rollbackCalls)
	}
	if logFilePath != "/tmp/rollback.log" {
		t.Fatalf("expected rollback log file path to be forwarded, got %q", logFilePath)
	}
}

func TestRun_VersionPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		for _, alias := range []string{"version", "-v", "-V", "--version", "-version"} {
			t.Run(alias, func(t *testing.T) {
				restore := stubHandlers()
				defer restore()

				resolveVerCmd = func() (cli.SemVer, int, error) {
					return cli.SemVer{Major: 1, Minor: 2, Patch: 3}, 1, nil
				}
				var out bytes.Buffer
				logInfof = func(format string, args ...any) {
					_, _ = fmt.Fprintf(&out, format, args...)
				}
				logErrorf = func(format string, args ...any) {
					t.Fatalf("unexpected error log: "+format, args...)
				}

				code := run([]string{"hardline", alias})
				if code != 0 {
					t.Fatalf("expected exit code 0, got %d", code)
				}
				if got := out.String(); got != "hardline version 1.2.3\n" {
					t.Fatalf("unexpected version output: %q", got)
				}
			})
		}
	})

	t.Run("help", func(t *testing.T) {
		restore := stubHandlers()
		defer restore()

		var usageCalls int
		showCommandUsage = func(command string) {
			usageCalls++
			if command != "version" {
				t.Fatalf("expected version help, got %q", command)
			}
		}
		resolveVerCmd = func() (cli.SemVer, int, error) {
			t.Fatal("version resolver should not run for version help")
			return cli.SemVer{}, 0, nil
		}

		code := run([]string{"hardline", "version", "--help"})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}
		if usageCalls != 1 {
			t.Fatalf("expected version usage once, got %d", usageCalls)
		}
	})

	t.Run("error", func(t *testing.T) {
		restore := stubHandlers()
		defer restore()

		resolveVerCmd = func() (cli.SemVer, int, error) {
			return cli.SemVer{}, 0, fmt.Errorf("boom")
		}
		var out, errOut bytes.Buffer
		logInfof = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&out, format, args...)
		}
		logErrorf = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&errOut, format, args...)
		}

		code := run([]string{"hardline", "-v"})
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if out.Len() != 0 {
			t.Fatalf("expected empty stdout, got %q", out.String())
		}
		if got := errOut.String(); got == "" || !bytes.Contains([]byte(got), []byte("version check failed: boom")) {
			t.Fatalf("unexpected stderr output: %q", got)
		}
	})
}

func TestRun_PlanPluginLoadFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return fmt.Errorf("bad plugin") }

	var planCalled bool
	runPlan = func(cli.Command) error {
		planCalled = true
		return nil
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "plan", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if planCalled {
		t.Fatalf("plan handler should not run when plugin loading fails")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("plugin load failed: bad plugin")) {
		t.Fatalf("expected plugin load error output, got %q", got)
	}
}

func TestRun_ApplyPluginLoadFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return fmt.Errorf("bad plugin") }

	var planCalled, applyCalled bool
	runPlan = func(cli.Command) error {
		planCalled = true
		return nil
	}
	runApply = func(context.Context, cli.Command) error {
		applyCalled = true
		return nil
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "apply", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if planCalled || applyCalled {
		t.Fatalf("plan/apply handlers should not run when plugin loading fails: plan=%v apply=%v", planCalled, applyCalled)
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("plugin load failed: bad plugin")) {
		t.Fatalf("expected plugin load error output, got %q", got)
	}
}

func TestRun_LogFileSetupFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p", LogFile: "/tmp/hardline.log"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return nil, fmt.Errorf("disk full") }
	loadPlugins = func() error { t.Fatal("plugins should not load when log setup fails"); return nil }

	var planCalled bool
	runPlan = func(cli.Command) error {
		planCalled = true
		return nil
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "plan", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if planCalled {
		t.Fatal("plan should not run when log setup fails")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("log file setup failed: disk full")) {
		t.Fatalf("expected log setup error output, got %q", got)
	}
}

func TestRun_VerifyLogFileSetupFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p", LogFile: "/tmp/verify.log"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return nil, fmt.Errorf("readonly") }

	var verifyCalled bool
	runVerify = func(cli.Command) error {
		verifyCalled = true
		return nil
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "verify-profile", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if verifyCalled {
		t.Fatal("verify should not run when log setup fails")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("log file setup failed: readonly")) {
		t.Fatalf("expected verify log setup error output, got %q", got)
	}
}

func TestRun_RollbackLogFileSetupFailure(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "starter-secure-ubuntu-24.04-lts", LogFile: "/tmp/rollback.log"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return nil, fmt.Errorf("readonly") }

	var rollbackCalled bool
	runRollback = func(cli.Command) { rollbackCalled = true }
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "rollback", "starter-secure-ubuntu-24.04-lts"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if rollbackCalled {
		t.Fatal("rollback should not run when log setup fails")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("log file setup failed: readonly")) {
		t.Fatalf("expected rollback log setup error output, got %q", got)
	}
}

func TestMain_UsesExitFunc(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	prevArgs := os.Args
	defer func() { os.Args = prevArgs }()
	os.Args = []string{"hardline", "--help"}

	var usageCalls int
	showUsage = func() { usageCalls++ }

	exitCode := -1
	exitFunc = func(code int) {
		exitCode = code
	}

	main()

	if exitCode != 0 {
		t.Fatalf("expected main to exit 0 for help, got %d", exitCode)
	}
	if usageCalls != 1 {
		t.Fatalf("expected usage to be called once, got %d", usageCalls)
	}
}

func TestRun_PlanFailureIsLoggedOnce(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }
	runVerify = func(cli.Command) error { return nil }
	runPlan = func(cli.Command) error { return fmt.Errorf("plan boom") }
	runPlanNextSteps = func(cli.Command) {
		t.Fatal("plan next steps should not run after plan failure")
	}

	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "plan", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("plan failed: plan boom")) {
		t.Fatalf("expected plan failure output, got %q", got)
	}
}

func TestRun_PlanVerifyFailureStopsBeforePlan(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }
	runVerify = func(cli.Command) error { return fmt.Errorf("verify boom") }

	planCalled := false
	runPlan = func(cli.Command) error {
		planCalled = true
		return nil
	}
	runPlanNextSteps = func(cli.Command) {
		t.Fatal("plan next steps should not run after verify failure")
	}

	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "plan", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if planCalled {
		t.Fatal("plan handler should not run after verify failure")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("verify failed: verify boom")) {
		t.Fatalf("expected verify failure output, got %q", got)
	}
}

func TestRun_ApplyFailureStopsAfterPlan(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }

	var order []string
	runVerify = func(cli.Command) error {
		order = append(order, "verify")
		return nil
	}
	runPlan = func(cli.Command) error {
		order = append(order, "plan")
		return nil
	}
	runApply = func(context.Context, cli.Command) error {
		order = append(order, "apply")
		return fmt.Errorf("apply boom")
	}

	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "apply", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if want := []string{"verify", "plan", "apply"}; fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("unexpected handler order: got %v want %v", order, want)
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("apply failed: apply boom")) {
		t.Fatalf("expected apply failure output, got %q", got)
	}
}

func TestRun_ApplyPlanFailureStopsBeforeApply(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }
	runVerify = func(cli.Command) error { return nil }
	runPlan = func(cli.Command) error { return fmt.Errorf("plan boom") }

	applyCalled := false
	runApply = func(context.Context, cli.Command) error {
		applyCalled = true
		return nil
	}

	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "apply", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if applyCalled {
		t.Fatal("apply handler should not run after plan failure")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("plan failed: plan boom")) {
		t.Fatalf("expected apply plan failure output, got %q", got)
	}
}

func TestRun_RollbackVerifyFailureStopsBeforeRollback(t *testing.T) {
	restore := stubHandlers()
	defer restore()

	parseCmd = func(command string, args []string) cli.Command {
		return cli.Command{Name: command, Profile: "p"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return func() {}, nil }
	loadPlugins = func() error { return nil }
	runVerify = func(cli.Command) error { return fmt.Errorf("verify boom") }

	rollbackCalled := false
	runRollback = func(cli.Command) {
		rollbackCalled = true
	}

	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "rollback", "profile"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if rollbackCalled {
		t.Fatal("rollback handler should not run after verify failure")
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte("verify failed: verify boom")) {
		t.Fatalf("expected rollback verify failure output, got %q", got)
	}
}

func TestDefaultInstallSignalHandler(t *testing.T) {
	prevExit := exitFunc
	prevError := logErrorf
	defer func() {
		exitFunc = prevExit
		logErrorf = prevError
	}()

	var exitCode int
	exitCalled := make(chan struct{})
	exitFunc = func(code int) {
		exitCode = code
		close(exitCalled)
	}
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	ctx := defaultInstallSignalHandler()

	// First signal cancels the context.
	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(syscall.SIGINT)

	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context did not cancel after first signal")
	}

	// Second signal forces hard exit.
	_ = p.Signal(syscall.SIGINT)
	select {
	case <-exitCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("signal handler did not fire within timeout")
	}

	if exitCode != 130 {
		t.Fatalf("expected exit code 130, got %d", exitCode)
	}
	if !bytes.Contains(errOut.Bytes(), []byte("received")) {
		t.Fatalf("expected signal message, got %q", errOut.String())
	}
}

func stubHandlers() func() {
	prevParse := parseCmd
	prevUsage := showUsage
	prevCommandUsage := showCommandUsage
	prevPlan := runPlan
	prevPlanNextSteps := runPlanNextSteps
	prevApply := runApply
	prevRollback := runRollback
	prevVerify := runVerify
	prevSetDebug := setDebugMode
	prevUseLogFile := useLogFile
	prevVersion := resolveVerCmd
	prevLoadPlugins := loadPlugins
	prevInfo := logInfof
	prevError := logErrorf
	prevExit := exitFunc
	prevSignal := installSignalHandler

	// Stub signal handler to avoid side effects in tests.
	installSignalHandler = func() context.Context { return context.Background() }

	return func() {
		parseCmd = prevParse
		showUsage = prevUsage
		showCommandUsage = prevCommandUsage
		runPlan = prevPlan
		runPlanNextSteps = prevPlanNextSteps
		runApply = prevApply
		runRollback = prevRollback
		runVerify = prevVerify
		setDebugMode = prevSetDebug
		useLogFile = prevUseLogFile
		resolveVerCmd = prevVersion
		loadPlugins = prevLoadPlugins
		logInfof = prevInfo
		logErrorf = prevError
		exitFunc = prevExit
		installSignalHandler = prevSignal
	}
}
