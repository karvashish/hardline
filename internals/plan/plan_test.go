package plan

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
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
		prevRunStep := runPlanStep
		defer func() { runPlanStep = prevRunStep }()
		runPlanStep = func(_ *ssh.Client, _ *profile.Profile, step profile.Step) (StepPlan, error) {
			return StepPlan{
				StepID:   step.ID,
				StepType: step.PluginName(),
				Summary:  "ok",
			}, nil
		}

		p := &profile.Profile{
			ID:          "p1",
			DisplayName: "Test Profile",
			Version:     "1.0.0",
			OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{ID: "s1", Plugin: "unknown", Severity: "low", RiskClass: "none"},
					},
				},
			},
		}

		withCapturedStderr(func() {
			if err := planProfile(nil, p, planRunOptions{Host: "example-host"}); err != nil {
				t.Fatalf("planProfile failed: %v", err)
			}
		})
	})

	t.Run("step error bubbles up", func(t *testing.T) {
		registry := pluginapi.NewRegistry()
		if err := registry.Register(pluginapi.Plugin{
			Name:               "boom",
			InternalValidation: true,
			Apply:              func(pluginapi.ApplyContext, profile.Step) error { return nil },
			Plan: func(pluginapi.PlanContext, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, errors.New("plan boom")
			},
			Capture: func(pluginapi.CaptureContext, profile.Step) (pluginapi.CaptureResult, error) {
				return pluginapi.CaptureResult{}, nil
			},
		}); err != nil {
			t.Fatalf("register plugin: %v", err)
		}
		prevRunStep := runPlanStep
		defer func() { runPlanStep = prevRunStep }()
		runPlanStep = func(client *ssh.Client, p *profile.Profile, s profile.Step) (StepPlan, error) {
			return planStepWithRegistry(registry, client, p, s)
		}

		p := &profile.Profile{
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{ID: "bad", Plugin: "boom"},
					},
				},
			},
		}

		err := planProfile(nil, p, planRunOptions{Host: "example-host"})
		if err == nil || !strings.Contains(err.Error(), "plan boom") {
			t.Fatalf("expected plan handler error, got %v", err)
		}
	})

	t.Run("writes report artifact", func(t *testing.T) {
		prevRunStep := runPlanStep
		defer func() { runPlanStep = prevRunStep }()
		runPlanStep = func(_ *ssh.Client, _ *profile.Profile, step profile.Step) (StepPlan, error) {
			return StepPlan{
				StepID:          step.ID,
				StepType:        step.PluginName(),
				Severity:        "high",
				RiskClass:       "access",
				Noop:            2,
				Summary:         "firewall step: configure default deny",
				OperatorSummary: "Configure default deny firewall policy",
				Highlights:      []string{"nftables.conf include is missing"},
			}, nil
		}

		p := &profile.Profile{
			ID:          "p1",
			DisplayName: "Test Profile",
			Version:     "1.0.0",
			OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
			ActionFiles: []profile.ActionFile{
				{
					Steps: []profile.Step{
						{ID: "s1", Plugin: "firewall", Severity: "high", RiskClass: "access"},
					},
				},
			},
		}

		reportPath := filepath.Join(t.TempDir(), "reports", "plan.yaml")
		withCapturedStderr(func() {
			if err := planProfile(nil, p, planRunOptions{
				Host:       "example-host",
				ReportFile: reportPath,
			}); err != nil {
				t.Fatalf("planProfile failed: %v", err)
			}
		})

		data, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("read report: %v", err)
		}
		text := string(data)
		if !strings.Contains(text, "kind: hardline_plan") || !strings.Contains(text, "operator_summary: Configure default deny firewall policy") {
			t.Fatalf("unexpected report contents %q", text)
		}
	})
}

func TestPrintPlan(t *testing.T) {
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
			Noop:      2,
			Summary:   "render file",
			Details:   []string{"line1", "line2"},
			Diff:      []string{"mode /etc/example.conf: 0600 -> 0644"},
		},
	}

	out := renderPlan(p, steps, "host-1", true)
	if !strings.Contains(out, "SUMMARY") || !strings.Contains(out, "ACTIONS") {
		t.Fatalf("expected detailed plan sections, got %q", out)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "Details") || !strings.Contains(out, "Final State Diff") || !strings.Contains(out, "Change planned") {
		t.Fatalf("expected detailed plan output, got %q", out)
	}
}

func TestRenderCompactPlan(t *testing.T) {
	p := profile.Profile{
		ID:          "base-secure-ubuntu-24.04-lts",
		DisplayName: "Base Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			StepID:          "firewall-default-deny",
			StepType:        "firewall",
			Severity:        "high",
			RiskClass:       "access",
			Noop:            2,
			Summary:         "firewall step (deterministic): backend=nftables table=inet filter",
			OperatorSummary: `Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)`,
			Highlights: []string{
				`nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`,
				"current nftables configuration: nft -c reports errors (Process exited with status 127)",
			},
		},
	}

	out := renderPlan(p, steps, "host-1", false)
	if !strings.Contains(out, "SUMMARY") || !strings.Contains(out, "NEEDS ATTENTION") {
		t.Fatalf("expected compact plan summary sections, got %q", out)
	}
	if !strings.Contains(out, "Risk breakdown") || !strings.Contains(out, "high 1") || !strings.Contains(out, "Needs attention") {
		t.Fatalf("expected compact risk summary, got %q", out)
	}
	if !strings.Contains(out, `firewall-default-deny: nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`) {
		t.Fatalf("expected compact key finding, got %q", out)
	}
	if strings.Contains(out, "ACTIONS") || strings.Contains(out, "Details") {
		t.Fatalf("did not expect verbose sections in compact plan, got %q", out)
	}
}

func TestRenderCompactStepResult(t *testing.T) {
	step := StepPlan{
		StepID:          "firewall-default-deny",
		StepType:        "firewall",
		Severity:        "high",
		RiskClass:       "access",
		Noop:            2,
		Summary:         `firewall step (deterministic): backend=nftables table=inet filter, managed_dest="/etc/nftables.d/99-hardline-firewall.nft", policies=1, rules=6`,
		OperatorSummary: `Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)`,
		Diff: []string{
			`chain input policy: accept -> drop`,
			`+ tcp dport 443 accept`,
		},
		Highlights: []string{
			`nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`,
		},
	}

	out := renderCompactStepResult(step)
	if !strings.Contains(out, `Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft"`) || !strings.Contains(out, "NEEDS ATTENTION") {
		t.Fatalf("expected stripped compact summary, got %q", out)
	}
	if !strings.Contains(normalizeLogText(out), "note: nftables.conf include") {
		t.Fatalf("expected surfaced note, got %q", out)
	}
	if !strings.Contains(normalizeLogText(out), "change: chain input policy: accept -> drop") {
		t.Fatalf("expected surfaced change preview, got %q", out)
	}
	if strings.Contains(out, "desired rules: 6") {
		t.Fatalf("did not expect non-actionable detail in compact output, got %q", out)
	}

	quiet := renderCompactStepResult(StepPlan{
		StepID:          "ssh-template-apply",
		StepType:        "template",
		Severity:        "medium",
		RiskClass:       "access",
		Noop:            0,
		Summary:         `template step: no rewrite required for "/etc/example.conf" (content and mode already match)`,
		OperatorSummary: `"/etc/example.conf" already matches the desired content and mode`,
	})
	if !strings.Contains(normalizeLogText(quiet), "ALREADY ALIGNED") {
		t.Fatalf("expected aligned label, got %q", quiet)
	}
	if strings.Contains(normalizeLogText(quiet), "note:") {
		t.Fatalf("did not expect no-op rewrite note, got %q", quiet)
	}
}

func TestPlanHelperBranches(t *testing.T) {
	t.Run("compact plan omits empty sections", func(t *testing.T) {
		p := profile.Profile{
			ID:          "p1",
			DisplayName: "Profile",
			Version:     "1.0.0",
			OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
		}
		steps := []StepPlan{
			{
				StepID:    "ssh-template-apply",
				StepType:  "template",
				Severity:  "medium",
				RiskClass: "access",
				Noop:      0,
				Summary:   `template step: no rewrite required for "/etc/example.conf" (content and mode already match)`,
			},
		}

		out := renderPlan(p, steps, "host-1", false)
		if strings.Contains(out, "CHANGES PLANNED") || strings.Contains(out, "NEEDS ATTENTION") {
			t.Fatalf("did not expect empty compact sections, got %q", out)
		}
	})

	t.Run("summary and disposition helpers", func(t *testing.T) {
		cases := []struct {
			name string
			step StepPlan
			want string
		}{
			{
				name: "operator summary wins",
				step: StepPlan{
					Summary:         `template step: render "src" to "/etc/example.conf" (mode 0644)`,
					OperatorSummary: `Write rendered configuration from "src" to "/etc/example.conf" with mode 0644`,
				},
				want: `Write rendered configuration from "src" to "/etc/example.conf" with mode 0644`,
			},
			{
				name: "fallback summary",
				step: StepPlan{
					Summary: `service step: enable ssh at boot`,
				},
				want: `Enable ssh at boot`,
			},
			{
				name: "plain summary passthrough",
				step: StepPlan{
					Summary: `plain summary`,
				},
				want: `Plain summary`,
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := compactOperatorSummary(tc.step)
				if got != tc.want {
					t.Fatalf("unexpected operator summary: got=%q want=%q", got, tc.want)
				}
			})
		}

		if got := compactStepSummary("plain summary"); got != "plain summary" {
			t.Fatalf("expected plain summary passthrough, got %q", got)
		}
		if got := countPlanSteps(nil); got != 0 {
			t.Fatalf("expected nil profile to have zero steps, got %d", got)
		}
		if got := countPlanSteps(&profile.Profile{ActionFiles: []profile.ActionFile{{Steps: []profile.Step{{}, {}}}, {Steps: []profile.Step{{}}}}}); got != 3 {
			t.Fatalf("expected counted steps, got %d", got)
		}
		if dispositionColor(dispositionAligned) != logger.ColorGreen ||
			dispositionColor(dispositionAttention) != logger.ColorRed ||
			dispositionColor(dispositionPlanned) != logger.ColorBlue {
			t.Fatal("unexpected disposition colors")
		}
		if dispositionText(dispositionAligned) != "already aligned" ||
			dispositionText(dispositionAttention) != "needs attention" ||
			dispositionText(dispositionPlanned) != "change planned" {
			t.Fatal("unexpected disposition text")
		}
		if got := upperFirst(""); got != "" {
			t.Fatalf("expected empty upperFirst result, got %q", got)
		}
	})

	t.Run("detail classification and breakdown helpers", func(t *testing.T) {
		highlights := []string{
			logger.ColorRed + "failed to preview upgrades" + logger.ColorReset,
			logger.ColorRed + `cannot compare content for "/etc/example.conf"` + logger.ColorReset,
			logger.ColorRed + "failed to preview upgrades" + logger.ColorReset,
		}
		got := normalizedHighlights(highlights)
		if len(got) != 2 || !strings.Contains(got[0], "failed") || !strings.Contains(got[1], "cannot compare content") {
			t.Fatalf("unexpected highlights: %#v", got)
		}

		if got := renderSeverityBreakdown([]StepPlan{{Severity: ""}, {Severity: "custom"}}); got != "low 1, unknown 1" {
			t.Fatalf("unexpected severity breakdown %q", got)
		}

		counts := dispositionCounts([]StepPlan{
			{Noop: 0},
			{Noop: 2},
			{Noop: 2, Highlights: []string{logger.ColorRed + "failed to preview upgrades" + logger.ColorReset}},
		})
		if counts[dispositionAligned] != 1 || counts[dispositionPlanned] != 1 || counts[dispositionAttention] != 1 {
			t.Fatalf("unexpected disposition counts: %#v", counts)
		}
		if stepDispositionFor(StepPlan{Noop: 0}) != dispositionAligned {
			t.Fatal("expected noop step to be aligned")
		}
		if stepDispositionFor(StepPlan{Noop: 2}) != dispositionPlanned {
			t.Fatal("expected changed step to be planned")
		}
		if stepDispositionFor(StepPlan{Noop: 2, Highlights: []string{logger.ColorRed + "failed to preview upgrades" + logger.ColorReset}}) != dispositionAttention {
			t.Fatal("expected actionable detail to require attention")
		}
		lines := normalizedReportLines([]string{
			logger.ColorGreen + "line one" + logger.ColorReset,
			logger.ColorGreen + "line one" + logger.ColorReset,
			"line two",
		})
		if len(lines) != 2 || lines[0] != "line one" || lines[1] != "line two" {
			t.Fatalf("unexpected normalized report lines %#v", lines)
		}
	})
}

func TestReportRenderingAndValidation(t *testing.T) {
	p := profile.Profile{
		ID:          "base-secure-ubuntu-24.04-lts",
		DisplayName: "Base Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			StepID:          "ssh-template-apply",
			StepType:        "template",
			Severity:        "medium",
			RiskClass:       "access",
			Noop:            0,
			Summary:         `template step: no rewrite required for "/etc/ssh/sshd_config"`,
			OperatorSummary: `"/etc/ssh/sshd_config" already matches the desired content and mode`,
			Details:         []string{logger.ColorGreen + "already present" + logger.ColorReset},
		},
		{
			StepID:          "firewall-default-deny",
			StepType:        "firewall",
			Severity:        "high",
			RiskClass:       "access",
			Noop:            2,
			Summary:         `firewall step: configure default deny`,
			OperatorSummary: `Configure nftables default deny policy`,
			Diff:            []string{`chain input policy: accept -> drop`},
			Highlights:      []string{logger.ColorRed + `nftables.conf include "/etc/nftables.d/*.nft" is missing` + logger.ColorReset},
		},
	}

	report := buildPlanReport(p, steps, "host-1")
	if report.Kind != "hardline_plan" || report.Summary.StepsInspected != 2 {
		t.Fatalf("unexpected report summary %+v", report.Summary)
	}
	if report.Summary.AlreadyAligned != 1 || report.Summary.NeedsAttention != 1 {
		t.Fatalf("unexpected report counts %+v", report.Summary)
	}
	if report.NextSteps.ApplyCommand != "hardline apply base-secure-ubuntu-24.04-lts --host host-1" {
		t.Fatalf("unexpected apply command %q", report.NextSteps.ApplyCommand)
	}

	jsonBody, err := renderPlanArtifact(report, "json")
	if err != nil {
		t.Fatalf("render json report: %v", err)
	}
	var decoded planFileReport
	if err := json.Unmarshal(jsonBody, &decoded); err != nil {
		t.Fatalf("decode json report: %v", err)
	}
	if decoded.Steps[1].Status != "needs_attention" {
		t.Fatalf("expected status in JSON report, got %+v", decoded.Steps[1])
	}
	if len(decoded.Steps[1].Diff) != 1 || decoded.Steps[1].Diff[0] != "chain input policy: accept -> drop" {
		t.Fatalf("expected diff in JSON report, got %+v", decoded.Steps[1])
	}

	yamlBody, err := renderPlanArtifact(report, "yaml")
	if err != nil {
		t.Fatalf("render yaml report: %v", err)
	}
	if text := string(yamlBody); !strings.Contains(text, "kind: hardline_plan") || !strings.Contains(text, "needs_attention") {
		t.Fatalf("unexpected yaml report %q", text)
	}

	mdBody, err := renderPlanArtifact(report, "md")
	if err != nil {
		t.Fatalf("render markdown report: %v", err)
	}
	if text := string(mdBody); !strings.Contains(text, "# Hardline Plan Report") || !strings.Contains(text, "## Steps") || !strings.Contains(text, "Configure nftables default deny policy") || !strings.Contains(text, "Final state diff") {
		t.Fatalf("unexpected markdown report %q", text)
	}

	if format, err := resolveReportFormat("report.json", ""); err != nil || format != "json" {
		t.Fatalf("expected inferred json format, got format=%q err=%v", format, err)
	}
	if format, err := resolveReportFormat("report.any", "markdown"); err != nil || format != "md" {
		t.Fatalf("expected explicit markdown format, got format=%q err=%v", format, err)
	}
	if _, err := resolveReportFormat("report.json", "toml"); err == nil || !strings.Contains(err.Error(), "unsupported report format") {
		t.Fatalf("expected invalid explicit format error, got %v", err)
	}
	if _, err := resolveReportFormat("report.out", ""); err == nil || !strings.Contains(err.Error(), "unsupported report format") {
		t.Fatalf("expected extension inference error, got %v", err)
	}
	if err := validatePlanOutputs(cli.Command{ReportFormat: "json"}); err == nil || !strings.Contains(err.Error(), "--report-format requires --report-file") {
		t.Fatalf("expected report config validation error, got %v", err)
	}
	if err := validatePlanOutputs(cli.Command{ReportFile: "report.yaml"}); err != nil {
		t.Fatalf("expected inferred report config to pass, got %v", err)
	}
	if err := validatePlanOutputs(cli.Command{ReportFile: "report.yaml", ReportFormat: "yaml"}); err != nil {
		t.Fatalf("expected explicit report config to pass, got %v", err)
	}
	if got := applyCommand("profile-1", ""); got != "hardline apply profile-1" {
		t.Fatalf("unexpected apply command without host %q", got)
	}
	if got := rollbackCommand(""); got != "hardline rollback last" {
		t.Fatalf("unexpected rollback command without host %q", got)
	}
	if got := displayTargetHost(""); got != "(host not set)" {
		t.Fatalf("unexpected display target host %q", got)
	}
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
	prevEnsurePlugins := ensurePlanPlugins
	prevExit := exitPlan
	defer func() {
		loadPlanProfile = prevLoad
		planVersionCmd = prevVer
		planCompareSemVer = prevCmp
		newPlanSSHClient = prevSSH
		runPlanForProfile = prevRunProfile
		ensurePlanPlugins = prevEnsurePlugins
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
	runPlanForProfile = func(*ssh.Client, *profile.Profile, planRunOptions) error { return nil }

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

	t.Run("report output config error", func(t *testing.T) {
		if code, exited := run(cli.Command{Profile: "x", Debug: true, ReportFormat: "json"}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
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

	t.Run("required plugin missing", func(t *testing.T) {
		ensurePlanPlugins = func(*profile.Profile) error { return errors.New("required plugin missing") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		ensurePlanPlugins = registry.EnsureProfilePlugins
	})

	t.Run("connect failure", func(t *testing.T) {
		newPlanSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, errors.New("connect fail") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		newPlanSSHClient = func(connection.Config) (*ssh.Client, error) { return nil, nil }
	})

	t.Run("plan profile failure", func(t *testing.T) {
		runPlanForProfile = func(*ssh.Client, *profile.Profile, planRunOptions) error { return errors.New("plan fail") }
		if code, exited := run(cli.Command{Profile: "x", Debug: true}); !exited || code != 1 {
			t.Fatalf("expected exit(1), got exited=%v code=%d", exited, code)
		}
		runPlanForProfile = func(*ssh.Client, *profile.Profile, planRunOptions) error { return nil }
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
