package cli

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestUsage_LogsHelp(t *testing.T) {
	restore := stubCLIHooks()
	defer restore()

	var out strings.Builder
	infof = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format, args...)
	}

	Usage()
	got := out.String()
	if !strings.Contains(got, "Usage:") || !strings.Contains(got, "hardline <command>") {
		t.Fatalf("expected usage text, got %q", got)
	}
	if !strings.Contains(got, "--help") || !strings.Contains(got, "-h") {
		t.Fatalf("expected help flags in usage, got %q", got)
	}
	if !strings.Contains(got, "verify <profile>") {
		t.Fatalf("expected verify alias in usage, got %q", got)
	}
	if !strings.Contains(got, "rollback <profile>") {
		t.Fatalf("expected rollback command in usage, got %q", got)
	}
}

func TestUsageFor_Subcommands(t *testing.T) {
	tests := []struct {
		name        string
		command     string
		want        string
		notExpected string
	}{
		{name: "apply", command: "apply", want: "hardline apply <profile>", notExpected: "hardline rollback <profile>"},
		{name: "rollback", command: "rollback", want: "hardline rollback <profile>", notExpected: "hardline apply <profile>"},
		{name: "verify alias", command: "vp", want: "hardline verify-profile <profile>", notExpected: "hardline plan <profile>"},
		{name: "version", command: "version", want: "hardline --version", notExpected: "hardline apply <profile>"},
		{name: "unknown falls back to root", command: "nope", want: "hardline <command> [args]", notExpected: "unknown command"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := stubCLIHooks()
			defer restore()

			var out strings.Builder
			infof = func(format string, args ...any) {
				_, _ = fmt.Fprintf(&out, format, args...)
			}

			UsageFor(tt.command)
			got := out.String()
			if !strings.Contains(got, tt.want) {
				t.Fatalf("expected %q in usage output, got %q", tt.want, got)
			}
			if tt.notExpected != "" && strings.Contains(got, tt.notExpected) {
				t.Fatalf("did not expect %q in usage output, got %q", tt.notExpected, got)
			}
		})
	}
}

func TestUsageFor_RollbackOverlapNoteFollowsForceRollback(t *testing.T) {
	restore := stubCLIHooks()
	defer restore()

	var out strings.Builder
	infof = func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format, args...)
	}

	UsageFor("rollback")
	got := out.String()
	force := strings.Index(got, "--force-rollback ")
	note := strings.Index(got, "(use when another profile")
	local := strings.Index(got, "--local-journal ")
	if force < 0 || note < 0 || local < 0 {
		t.Fatalf("expected both rollback flags and the overlap note, got %q", got)
	}
	if force > note || note > local {
		t.Fatalf("expected the overlap note to sit under --force-rollback, got %q", got)
	}
}

func TestParse_ExitPaths(t *testing.T) {
	t.Run("missing profile", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		var errOut strings.Builder
		errorf = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&errOut, format, args...)
		}
		exitCode := 0
		exitFunc = func(code int) { exitCode = code }

		got := Parse("plan", nil)
		if exitCode != 1 {
			t.Fatalf("expected exit code 1, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on exit path, got %+v", got)
		}
		if !strings.Contains(errOut.String(), "requires a profile") {
			t.Fatalf("expected missing profile message, got %q", errOut.String())
		}
	})

	t.Run("subcommand help", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		var out strings.Builder
		infof = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&out, format, args...)
		}
		exitCode := -1
		exitFunc = func(code int) { exitCode = code }

		got := Parse("plan", []string{"--help"})
		if exitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on help path, got %+v", got)
		}
		if got := out.String(); !strings.Contains(got, "hardline plan <profile>") || strings.Contains(got, "hardline apply <profile>") {
			t.Fatalf("expected plan-specific usage text on help path, got %q", got)
		}
	})

	t.Run("subcommand shorthand help", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		var out strings.Builder
		infof = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&out, format, args...)
		}
		exitCode := -1
		exitFunc = func(code int) { exitCode = code }

		got := Parse("plan", []string{"-h"})
		if exitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on help path, got %+v", got)
		}
		if got := out.String(); !strings.Contains(got, "hardline plan <profile>") || strings.Contains(got, "--host, -h HOST") {
			t.Fatalf("expected plan-specific usage text with -H host shorthand, got %q", got)
		}
	})

	t.Run("subcommand help after profile", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		var out strings.Builder
		infof = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&out, format, args...)
		}
		exitCode := -1
		exitFunc = func(code int) { exitCode = code }

		got := Parse("verify", []string{"staging", "--help"})
		if exitCode != 0 {
			t.Fatalf("expected exit code 0, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on help path, got %+v", got)
		}
		if got := out.String(); !strings.Contains(got, "hardline verify-profile <profile>") || strings.Contains(got, "hardline plan <profile>") {
			t.Fatalf("expected verify-specific usage text on help path, got %q", got)
		}
	})

	t.Run("surplus positional argument", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		var errOut strings.Builder
		errorf = func(format string, args ...any) {
			_, _ = fmt.Fprintf(&errOut, format, args...)
		}
		exitCode := 0
		exitFunc = func(code int) { exitCode = code }

		got := Parse("apply", []string{"profile", "surplus", "--keep-local-rollback"})
		if exitCode != 2 {
			t.Fatalf("expected exit code 2, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on surplus argument, got %+v", got)
		}
		if !strings.Contains(errOut.String(), `unexpected argument "surplus"`) {
			t.Fatalf("expected the surplus argument to be named, got %q", errOut.String())
		}
	})

	t.Run("flag parse error", func(t *testing.T) {
		restore := stubCLIHooks()
		defer restore()

		exitCode := 0
		exitFunc = func(code int) { exitCode = code }

		got := Parse("plan", []string{"profile", "--bad-flag"})
		if exitCode != 2 {
			t.Fatalf("expected exit code 2, got %d", exitCode)
		}
		if !reflect.DeepEqual(got, Command{}) {
			t.Fatalf("expected zero command on parse error, got %+v", got)
		}
	})
}

func TestParse_SuccessPaths(t *testing.T) {
	restore := stubCLIHooks()
	defer restore()

	exitFunc = func(int) { t.Fatal("exit should not be called") }

	planCmd := Parse("plan", []string{
		"prod",
		"--host", "example.com",
		"--user", "deployer",
		"--keypath", "/tmp/key",
		"--log-file", "/tmp/hardline.log",
		"--report-file", "/tmp/hardline-report.json",
		"--report-format", "json",
		"--debug",
	})
	if planCmd.Name != "plan" ||
		planCmd.Profile != "prod" ||
		planCmd.Host != "example.com" ||
		planCmd.User != "deployer" ||
		planCmd.KeyPath != "/tmp/key" ||
		planCmd.LogFile != "/tmp/hardline.log" ||
		planCmd.ReportFile != "/tmp/hardline-report.json" ||
		planCmd.ReportFormat != "json" ||
		!planCmd.Debug {
		t.Fatalf("unexpected parsed plan command: %+v", planCmd)
	}

	applyCmd := Parse("apply", []string{
		"prod",
		"--host", "example.com",
		"--user", "deployer",
		"--keypath", "/tmp/key",
		"--keep-local-rollback",
	})
	if applyCmd.Name != "apply" ||
		applyCmd.Profile != "prod" ||
		applyCmd.Host != "example.com" ||
		applyCmd.User != "deployer" ||
		applyCmd.KeyPath != "/tmp/key" ||
		!applyCmd.KeepLocalRollback {
		t.Fatalf("unexpected parsed apply command: %+v", applyCmd)
	}

	verifyCmd := Parse("verify-profile", []string{"staging", "--log-file", "/tmp/verify.log", "-d"})
	if verifyCmd.Name != "verify-profile" || verifyCmd.Profile != "staging" || !verifyCmd.Debug {
		t.Fatalf("unexpected parsed verify command: %+v", verifyCmd)
	}
	if verifyCmd.Host != "" || verifyCmd.User != "" || verifyCmd.KeyPath != "" || verifyCmd.LogFile != "/tmp/verify.log" {
		t.Fatalf("verify command should not parse host/user/key fields: %+v", verifyCmd)
	}

	rollbackCmd := Parse("rollback", []string{
		"last",
		"-H", "example.com",
		"-u", "deployer",
		"-k", "/tmp/key",
		"--log-file", "/tmp/rollback.log",
	})
	if rollbackCmd.Name != "rollback" || rollbackCmd.Profile != "last" || rollbackCmd.Host != "example.com" || rollbackCmd.User != "deployer" || rollbackCmd.KeyPath != "/tmp/key" || rollbackCmd.LogFile != "/tmp/rollback.log" {
		t.Fatalf("unexpected parsed rollback command: %+v", rollbackCmd)
	}

	localKeyCmd := Parse("verify-profile", []string{"myprofile", "--allow-local-key"})
	if !localKeyCmd.AllowLocalKey {
		t.Fatalf("expected AllowLocalKey=true, got %+v", localKeyCmd)
	}

	planLocalKeyCmd := Parse("plan", []string{"prod", "--host", "example.com", "--allow-local-key"})
	if !planLocalKeyCmd.AllowLocalKey || planLocalKeyCmd.Host != "example.com" {
		t.Fatalf("expected AllowLocalKey=true with host, got %+v", planLocalKeyCmd)
	}

	portCmd := Parse("plan", []string{"prod", "--host", "example.com", "--port", "2222", "-u", "deploy", "-k", "/tmp/key"})
	if portCmd.Port != 2222 || portCmd.Host != "example.com" {
		t.Fatalf("expected port=2222 with host, got %+v", portCmd)
	}

	shortPortCmd := Parse("apply", []string{"prod", "-H", "example.com", "-p", "8022", "-u", "deploy", "-k", "/tmp/key"})
	if shortPortCmd.Port != 8022 {
		t.Fatalf("expected port=8022 with -p shorthand, got %+v", shortPortCmd)
	}
	if shortPortCmd.Host != "example.com" {
		t.Fatalf("expected host to parse from -H shorthand, got %+v", shortPortCmd)
	}

	fileCmd := Parse("plan", []string{
		"prod",
		"--overrides-file", "/tmp/dev-overrides.json",
	})
	if fileCmd.OverridesFile != "/tmp/dev-overrides.json" {
		t.Fatalf("expected overrides file to parse, got %+v", fileCmd)
	}
}

func TestVersionCmd_AndSemVerHelpers(t *testing.T) {
	t.Run("version cmd success", func(t *testing.T) {
		ver, schema, err := VersionCmd()
		if err != nil {
			t.Fatalf("VersionCmd failed: %v", err)
		}
		if ver.String() == "" {
			t.Fatal("expected non-empty semantic version")
		}
		if schema <= 0 {
			t.Fatalf("expected positive profile schema, got %d", schema)
		}
	})

	t.Run("version cmd error branches", func(t *testing.T) {
		restoreVersionJSON := versionJSON
		t.Cleanup(func() { versionJSON = restoreVersionJSON })

		versionJSON = nil
		if _, _, err := VersionCmd(); err == nil || !strings.Contains(err.Error(), "empty") {
			t.Fatalf("expected empty embedded version error, got %v", err)
		}

		versionJSON = []byte("{bad json")
		if _, _, err := VersionCmd(); err == nil {
			t.Fatal("expected invalid JSON error")
		}

		versionJSON = []byte(`{"profile_schema":1}`)
		if _, _, err := VersionCmd(); err == nil || !strings.Contains(err.Error(), "version field") {
			t.Fatalf("expected invalid version field error, got %v", err)
		}

		versionJSON = []byte(`{"version":"x","profile_schema":1}`)
		if _, _, err := VersionCmd(); err == nil || !strings.Contains(err.Error(), "invalid semver") {
			t.Fatalf("expected invalid semver error, got %v", err)
		}
	})

	t.Run("parse semver", func(t *testing.T) {
		v, err := ParseSemVer("v1.2.3")
		if err != nil {
			t.Fatalf("ParseSemVer failed: %v", err)
		}
		if v.Major != 1 || v.Minor != 2 || v.Patch != 3 {
			t.Fatalf("unexpected semver: %+v", v)
		}

		bad := []string{"1.2", "a.2.3", "1.b.3", "1.2.c", "1.2.3-", "1.2.3-rc 1", "1.2.3-rc_1"}
		for _, in := range bad {
			if _, err := ParseSemVer(in); err == nil {
				t.Fatalf("expected ParseSemVer(%q) to fail", in)
			}
		}
	})

	t.Run("parse semver prerelease", func(t *testing.T) {
		v, err := ParseSemVer("v0.2.0-rc1")
		if err != nil {
			t.Fatalf("ParseSemVer failed: %v", err)
		}
		if v.Major != 0 || v.Minor != 2 || v.Patch != 0 || v.Pre != "rc1" {
			t.Fatalf("unexpected semver: %+v", v)
		}
		if got := v.String(); got != "0.2.0-rc1" {
			t.Fatalf("expected prerelease preserved in String, got %q", got)
		}

		v, err = ParseSemVer("0.2.0-beta.2")
		if err != nil {
			t.Fatalf("ParseSemVer failed: %v", err)
		}
		if v.Pre != "beta.2" {
			t.Fatalf("unexpected prerelease: %q", v.Pre)
		}

		v, err = ParseSemVer("1.2.3")
		if err != nil {
			t.Fatalf("ParseSemVer failed: %v", err)
		}
		if v.Pre != "" || v.String() != "1.2.3" {
			t.Fatalf("unexpected release semver: %+v", v)
		}
	})

	t.Run("compare semver", func(t *testing.T) {
		if got, err := CompareSemVer("1.2.3", "1.2.3"); err != nil || got != 0 {
			t.Fatalf("expected equality compare, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("1.2.3", "2.0.0"); err != nil || got != -1 {
			t.Fatalf("expected less-than compare, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("2.0.0", "1.2.3"); err != nil || got != 1 {
			t.Fatalf("expected greater-than compare, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("1.2.3", "1.3.0"); err != nil || got != -1 {
			t.Fatalf("expected minor less-than compare, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("1.2.4", "1.2.3"); err != nil || got != 1 {
			t.Fatalf("expected patch greater-than compare, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("0.2.0-rc1", "0.2.0"); err != nil || got != 0 {
			t.Fatalf("expected prerelease to compare equal to its release, got=%d err=%v", got, err)
		}
		if got, err := CompareSemVer("0.2.0-rc1", "0.3.0"); err != nil || got != -1 {
			t.Fatalf("expected prerelease minor less-than compare, got=%d err=%v", got, err)
		}
		if _, err := CompareSemVer("bad", "1.0.0"); err == nil {
			t.Fatal("expected compare parse error")
		}
		if _, err := CompareSemVer("1.0.0", "bad"); err == nil {
			t.Fatal("expected compare parse error for second semver")
		}
	})
}

func stubCLIHooks() func() {
	prevInfo := infof
	prevErr := errorf
	prevExit := exitFunc
	return func() {
		infof = prevInfo
		errorf = prevErr
		exitFunc = prevExit
	}
}
