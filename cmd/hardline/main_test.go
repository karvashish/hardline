package main

import (
	"bytes"
	"fmt"
	"testing"

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
		return cli.Command{Name: command, Profile: "p", Debug: true}
	}

	var debugSet bool
	setDebugMode = func(debug bool) { debugSet = debug }
	var logFilePath string
	useLogFile = func(path string) (func(), error) {
		logFilePath = path
		return func() {}, nil
	}
	loadPlugins = func() error { return nil }

	var planCalled bool
	runPlan = func(c cli.Command) {
		if c.Name != "plan" {
			t.Fatalf("unexpected command passed to plan: %+v", c)
		}
		planCalled = true
	}
	runApply = func(cli.Command) { t.Fatal("apply handler should not be called for plan command") }
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
	if !planCalled {
		t.Fatal("expected plan handler to be called")
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
	runPlan = func(cli.Command) { order = append(order, "plan") }
	runApply = func(cli.Command) { order = append(order, "apply") }
	runRollback = func(cli.Command) { t.Fatal("rollback handler should not be called for apply command") }

	code := run([]string{"hardline", "apply", "profile"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if len(order) != 2 || order[0] != "plan" || order[1] != "apply" {
		t.Fatalf("expected order [plan apply], got %#v", order)
	}
	if logFilePath != "/tmp/hardline.log" {
		t.Fatalf("expected log file path to be forwarded, got %q", logFilePath)
	}
}

func TestRun_VerifyDispatch(t *testing.T) {
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
	runVerify = func(c cli.Command) {
		verifyCalls++
		if c.Name != "vp" {
			t.Fatalf("expected verify alias name vp, got %q", c.Name)
		}
	}

	code := run([]string{"hardline", "vp", "profile"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected verify call once, got %d", verifyCalls)
	}
	if logFilePath != "/tmp/verify.log" {
		t.Fatalf("expected verify log file path to be forwarded, got %q", logFilePath)
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
	runVerify = func(cli.Command) { verifyCalled = true }
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
		return cli.Command{Name: command, Profile: "last", LogFile: "/tmp/rollback.log"}
	}
	setDebugMode = func(bool) {}
	var logFilePath string
	useLogFile = func(path string) (func(), error) {
		logFilePath = path
		return func() {}, nil
	}

	var rollbackCalls int
	runRollback = func(c cli.Command) {
		rollbackCalls++
		if c.Name != "rollback" {
			t.Fatalf("expected rollback command name, got %q", c.Name)
		}
	}
	runPlan = func(cli.Command) { t.Fatal("plan handler should not be called for rollback command") }
	runApply = func(cli.Command) { t.Fatal("apply handler should not be called for rollback command") }

	code := run([]string{"hardline", "rollback", "last"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
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

		code := run([]string{"hardline", "version"})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}
		if got := out.String(); got != "hardline version 1.2.3\n" {
			t.Fatalf("unexpected version output: %q", got)
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
	runPlan = func(cli.Command) { planCalled = true }
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
	runPlan = func(cli.Command) { planCalled = true }
	runApply = func(cli.Command) { applyCalled = true }
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
	runPlan = func(cli.Command) { planCalled = true }
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
	runVerify = func(cli.Command) { verifyCalled = true }
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
		return cli.Command{Name: command, Profile: "last", LogFile: "/tmp/rollback.log"}
	}
	setDebugMode = func(bool) {}
	useLogFile = func(string) (func(), error) { return nil, fmt.Errorf("readonly") }

	var rollbackCalled bool
	runRollback = func(cli.Command) { rollbackCalled = true }
	var errOut bytes.Buffer
	logErrorf = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&errOut, format, args...)
	}

	code := run([]string{"hardline", "rollback", "last"})
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

func stubHandlers() func() {
	prevParse := parseCmd
	prevUsage := showUsage
	prevPlan := runPlan
	prevApply := runApply
	prevRollback := runRollback
	prevVerify := runVerify
	prevSetDebug := setDebugMode
	prevUseLogFile := useLogFile
	prevVersion := resolveVerCmd
	prevLoadPlugins := loadPlugins
	prevInfo := logInfof
	prevError := logErrorf

	return func() {
		parseCmd = prevParse
		showUsage = prevUsage
		runPlan = prevPlan
		runApply = prevApply
		runRollback = prevRollback
		runVerify = prevVerify
		setDebugMode = prevSetDebug
		useLogFile = prevUseLogFile
		resolveVerCmd = prevVersion
		loadPlugins = prevLoadPlugins
		logInfof = prevInfo
		logErrorf = prevError
	}
}
