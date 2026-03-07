package cli

import (
	"fmt"
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
	if !strings.Contains(got, "rollback last") {
		t.Fatalf("expected rollback command in usage, got %q", got)
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
		if got != (Command{}) {
			t.Fatalf("expected zero command on exit path, got %+v", got)
		}
		if !strings.Contains(errOut.String(), "requires a profile") {
			t.Fatalf("expected missing profile message, got %q", errOut.String())
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
		if got != (Command{}) {
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
		"--debug",
	})
	if planCmd.Name != "plan" || planCmd.Profile != "prod" || planCmd.Host != "example.com" || planCmd.User != "deployer" || planCmd.KeyPath != "/tmp/key" || !planCmd.Debug {
		t.Fatalf("unexpected parsed plan command: %+v", planCmd)
	}

	verifyCmd := Parse("verify-profile", []string{"staging", "-d"})
	if verifyCmd.Name != "verify-profile" || verifyCmd.Profile != "staging" || !verifyCmd.Debug {
		t.Fatalf("unexpected parsed verify command: %+v", verifyCmd)
	}
	if verifyCmd.Host != "" || verifyCmd.User != "" || verifyCmd.KeyPath != "" {
		t.Fatalf("verify command should not parse host/user/key fields: %+v", verifyCmd)
	}

	rollbackCmd := Parse("rollback", []string{
		"last",
		"-h", "example.com",
		"-u", "deployer",
		"-k", "/tmp/key",
	})
	if rollbackCmd.Name != "rollback" || rollbackCmd.Profile != "last" || rollbackCmd.Host != "example.com" || rollbackCmd.User != "deployer" || rollbackCmd.KeyPath != "/tmp/key" {
		t.Fatalf("unexpected parsed rollback command: %+v", rollbackCmd)
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

		bad := []string{"1.2", "a.2.3", "1.b.3", "1.2.c"}
		for _, in := range bad {
			if _, err := ParseSemVer(in); err == nil {
				t.Fatalf("expected ParseSemVer(%q) to fail", in)
			}
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
		if _, err := CompareSemVer("bad", "1.0.0"); err == nil {
			t.Fatal("expected compare parse error")
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
