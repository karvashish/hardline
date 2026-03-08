package plan

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestPlanProfile(t *testing.T) {
	prevDebug := logger.DebugMode()
	logger.SetDebug(true)
	defer logger.SetDebug(prevDebug)

	t.Run("success with unknown step", func(t *testing.T) {
		p := &profile.Profile{
			ID:          "p1",
			DisplayName: "Test Profile",
			Version:     "1.0.0",
			OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{ID: "s1", Type: "unknown", Severity: "low", RiskClass: "none"},
					},
				},
			},
		}

		withCapturedStderr(func() {
			if err := planProfile(nil, p, "example-host"); err != nil {
				t.Fatalf("planProfile failed: %v", err)
			}
		})
	})

	t.Run("step error bubbles up", func(t *testing.T) {
		prevRegistry := planPluginRegistry
		defer func() {
			planPluginRegistry = prevRegistry
		}()

		registry := pluginapi.NewRegistry()
		if err := registry.RegisterPlan(pluginapi.PlanHandler{
			Type: "boom",
			Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, errors.New("plan boom")
			},
		}); err != nil {
			t.Fatalf("register plan handler: %v", err)
		}
		planPluginRegistry = registry

		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{ID: "bad", Type: "boom"},
					},
				},
			},
		}

		err := planProfile(nil, p, "example-host")
		if err == nil || !strings.Contains(err.Error(), "plan boom") {
			t.Fatalf("expected plan handler error, got %v", err)
		}
	})
}

func TestPrintPlan(t *testing.T) {
	prevDebug := logger.DebugMode()
	logger.SetDebug(true)
	defer logger.SetDebug(prevDebug)

	p := profile.Profile{
		ID:          "base-secure-ubuntu-24.04-lts",
		DisplayName: "Base Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			StepID:    "s1",
			StepType:  "custom",
			Severity:  "medium",
			RiskClass: "integrity",
			Summary:   "render file",
			Details:   []string{"line1", "line2"},
		},
	}

	withCapturedStderr(func() {
		printPlan(p, steps, "host-1")
	})
}

func TestSeverityHelpers(t *testing.T) {
	if got := overallSeverity(nil); got != "low" {
		t.Fatalf("expected empty severity to default to low, got %q", got)
	}

	got := overallSeverity([]StepPlan{
		{Severity: "low"},
		{Severity: "medium"},
		{Severity: "high"},
	})
	if got != "high" {
		t.Fatalf("expected max severity high, got %q", got)
	}

	got = overallSeverity([]StepPlan{
		{Severity: "low"},
		{Severity: "critical"},
		{Severity: "high"},
	})
	if got != "critical" {
		t.Fatalf("expected critical short-circuit, got %q", got)
	}

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		colored := severityColor(sev)
		if !strings.Contains(colored, strings.ToUpper(sev)) {
			t.Fatalf("expected colored severity to contain %q, got %q", strings.ToUpper(sev), colored)
		}
	}
	if got := severityColor("custom"); got != "custom" {
		t.Fatalf("expected unknown severity passthrough, got %q", got)
	}
}

func TestPlan_WithStubbedDependencies(t *testing.T) {
	prevLoad := loadPlanProfile
	prevVer := planVersionCmd
	prevCmp := planCompareSemVer
	prevSSH := newPlanSSHClient
	prevRunProfile := runPlanForProfile
	prevExit := exitPlan
	defer func() {
		loadPlanProfile = prevLoad
		planVersionCmd = prevVer
		planCompareSemVer = prevCmp
		newPlanSSHClient = prevSSH
		runPlanForProfile = prevRunProfile
		exitPlan = prevExit
	}()

	exitPlan = func(code int) { panic(exitSignal{code: code}) }

	goodProfile := mustLoadFixtureProfile(t, profileFixture{
		ID:          "ok",
		DisplayName: "OK",
		MinHardline: "0.1.0",
		Schema:      1,
	})

	loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	newPlanSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, nil }
	runPlanForProfile = func(*ssh.Client, *profile.Profile, string) error { return nil }

	run := func(c cli.Command) (int, bool) {
		var (
			exitCode int
			exited   bool
		)
		func() {
			defer func() {
				if r := recover(); r != nil {
					sig, ok := r.(exitSignal)
					if !ok {
						panic(r)
					}
					exited = true
					exitCode = sig.code
				}
			}()
			Plan(c)
		}()
		return exitCode, exited
	}

	t.Run("profile load error", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) { return nil, errors.New("load fail") }
		if code, exited := run(cli.Command{Profile: "x", Debug: false}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("version command error", func(t *testing.T) {
		planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{}, 0, errors.New("bad version") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	})

	t.Run("compare error", func(t *testing.T) {
		planCompareSemVer = func(_, _ string) (int, error) { return 0, errors.New("bad semver") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	})

	t.Run("version too old", func(t *testing.T) {
		planCompareSemVer = func(_, _ string) (int, error) { return -1, nil }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	})

	t.Run("schema too new", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "0.1.0", ProfileSchema: 2}, nil
		}
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("affirm failure", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "0.1.0", ProfileSchema: 1}, nil
		}
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("connect failure", func(t *testing.T) {
		newPlanSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, errors.New("connect fail") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		newPlanSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, nil }
	})

	t.Run("plan profile failure", func(t *testing.T) {
		runPlanForProfile = func(*ssh.Client, *profile.Profile, string) error { return errors.New("plan fail") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		runPlanForProfile = func(*ssh.Client, *profile.Profile, string) error { return nil }
	})

	t.Run("success", func(t *testing.T) {
		if _, exited := run(cli.Command{Profile: "x", Host: "h1", User: "u1", KeyPath: "k1", Debug: false}); exited {
			t.Fatalf("did not expect exit on success path")
		}
	})
}

func withCapturedStderr(fn func()) string {
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	fn()

	_ = w.Close()
	os.Stderr = orig

	out, _ := io.ReadAll(r)
	_ = r.Close()
	return string(out)
}

type exitSignal struct {
	code int
}

type profileFixture struct {
	ID          string
	DisplayName string
	MinHardline string
	Schema      int
}

func writeProfileFixture(t *testing.T, f profileFixture) string {
	t.Helper()
	dir := t.TempDir()
	body := `{
  "id": "` + f.ID + `",
  "display_name": "` + f.DisplayName + `",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": ` + strconv.Itoa(f.Schema) + `,
  "min_hardline": "` + f.MinHardline + `",
  "actions": [],
  "templates": []
}`
	if err := os.WriteFile(filepath.Join(dir, "profile.json"), []byte(body), 0o644); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}
	return dir
}

func mustLoadFixtureProfile(t *testing.T, f profileFixture) *profile.Profile {
	t.Helper()
	dir := writeProfileFixture(t, f)
	p, err := profile.Load(dir)
	if err != nil {
		t.Fatalf("load fixture profile failed: %v", err)
	}
	return p
}
