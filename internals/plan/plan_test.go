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
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlanProfile(t *testing.T) {
	prevDebug := logger.DebugMode()
	logger.SetDebug(true)
	defer logger.SetDebug(prevDebug)

	t.Run("success with unknown step", func(t *testing.T) {
		prevRunStep := runPlanStep
		defer func() { runPlanStep = prevRunStep }()
		runPlanStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step, _ map[string]bool) (StepPlan, error) {
			return StepPlan{
				PlanResult: pluginapi.PlanResult{Summary: "ok"},
				StepID:     step.ID,
				StepType:   step.PluginName(),
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
						{ID: "s1", Plugin: "unknown"},
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
			Apply:              func(pluginapi.Context, profile.Step) error { return nil },
			Plan: func(pluginapi.Context, profile.Step) (pluginapi.PlanResult, error) {
				return pluginapi.PlanResult{}, errors.New("plan boom")
			},
			Capture: func(pluginapi.Context, profile.Step) (pluginapi.CaptureResult, error) {
				return pluginapi.CaptureResult{}, nil
			},
			Rollback:       func(pluginapi.Host, pluginapi.ObjectRecord) error { return nil },
			DetectConflict: func(pluginapi.Host, pluginapi.ObjectRecord) []string { return nil },
		}); err != nil {
			t.Fatalf("register plugin: %v", err)
		}
		prevRunStep := runPlanStep
		defer func() { runPlanStep = prevRunStep }()
		runPlanStep = func(_ *pluginapi.Registry, client *remote.Client, p *profile.Profile, s profile.Step, sc map[string]bool) (StepPlan, error) {
			return planStepWithRegistry(registry, client, p, s, sc)
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
		runPlanStep = func(_ *pluginapi.Registry, _ *remote.Client, _ *profile.Profile, step profile.Step, _ map[string]bool) (StepPlan, error) {
			return StepPlan{
				PlanResult: pluginapi.PlanResult{
					WillChange:      true,
					Summary:         "firewall step: configure default deny",
					OperatorSummary: "Configure default deny firewall policy",
					Highlights:      []string{"nftables.conf include is missing"},
				},
				StepID:   step.ID,
				StepType: step.PluginName(),
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
						{ID: "s1", Plugin: "firewall"},
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

func TestPrintPlanNextSteps(t *testing.T) {
	capture := func(fn func()) string {
		logFile := filepath.Join(t.TempDir(), "out.log")
		closeLog, err := logger.UseLogFile(logFile)
		if err != nil {
			t.Fatalf("UseLogFile: %v", err)
		}
		fn()
		closeLog()
		data, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("read log: %v", err)
		}
		return string(data)
	}

	out := capture(func() {
		PrintPlanNextSteps(cli.Command{
			Profile:       "my-profile",
			Host:          "10.0.0.1",
			OverridesFile: "overrides.json",
		})
	})
	if !strings.Contains(out, "NEXT STEPS") {
		t.Fatalf("expected NEXT STEPS section, got %q", out)
	}
	if !strings.Contains(out, `hardline apply my-profile --host 10.0.0.1 --overrides-file "overrides.json"`) {
		t.Fatalf("expected apply command with host and overrides-file, got %q", out)
	}
	if strings.Contains(out, "rollback") {
		t.Fatalf("did not expect rollback hint in plan next steps, got %q", out)
	}

	outNoHost := capture(func() { PrintPlanNextSteps(cli.Command{Profile: "my-profile"}) })
	if !strings.Contains(outNoHost, "hardline apply my-profile") {
		t.Fatalf("expected apply command without host, got %q", outNoHost)
	}
	if strings.Contains(outNoHost, "--host") {
		t.Fatalf("did not expect --host when host is empty, got %q", outNoHost)
	}
}

func TestPrintPlan(t *testing.T) {
	p := profile.Profile{
		ID:          "starter-secure-ubuntu-24.04-lts",
		DisplayName: "Starter Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			PlanResult: pluginapi.PlanResult{
				WillChange: true,
				Summary:    "render file",
				Details:    []string{"line1", "line2"},
				Diff:       []string{"mode /etc/example.conf: 0600 -> 0644"},
			},
			StepID:   "s1",
			StepType: "custom",
		},
	}

	out := renderDetailedPlan(p, steps, "host-1")
	if !strings.Contains(out, "SUMMARY") || !strings.Contains(out, "ACTIONS") {
		t.Fatalf("expected detailed plan sections, got %q", out)
	}
	if !strings.Contains(out, "line1") || !strings.Contains(out, "Details") || !strings.Contains(out, "Final State Diff") || !strings.Contains(out, "Change planned") {
		t.Fatalf("expected detailed plan output, got %q", out)
	}
}

func TestRenderCompactPlan(t *testing.T) {
	p := profile.Profile{
		ID:          "starter-secure-ubuntu-24.04-lts",
		DisplayName: "Starter Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			PlanResult: pluginapi.PlanResult{
				WillChange:      true,
				Summary:         "firewall step (deterministic): backend=nftables table=inet filter",
				OperatorSummary: `Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)`,
				Highlights: []string{
					`nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`,
					"current nftables configuration: nft -c reports errors (Process exited with status 127)",
				},
			},
			StepID:   "firewall-default-deny",
			StepType: "firewall",
		},
	}

	out := renderCompactPlan(p, steps, "host-1")
	if !strings.Contains(out, "SUMMARY") || !strings.Contains(out, "NEEDS ATTENTION") {
		t.Fatalf("expected compact plan summary sections, got %q", out)
	}
	if !strings.Contains(out, "Needs attention") || strings.Contains(out, "Risk breakdown") || strings.Contains(out, "Overall risk") {
		t.Fatalf("expected simplified compact summary, got %q", out)
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
		PlanResult: pluginapi.PlanResult{
			WillChange:      true,
			Summary:         `firewall step (deterministic): backend=nftables table=inet filter, managed_dest="/etc/nftables.d/99-hardline-firewall.nft", policies=1, rules=6`,
			OperatorSummary: `Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)`,
			Diff: []string{
				`chain input policy: accept -> drop`,
				`+ tcp dport 443 accept`,
			},
			Highlights: []string{
				`nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`,
			},
		},
		StepID:   "firewall-default-deny",
		StepType: "firewall",
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
		PlanResult: pluginapi.PlanResult{
			Summary:         `template step: no rewrite required for "/etc/example.conf" (content and mode already match)`,
			OperatorSummary: `"/etc/example.conf" already matches the desired content and mode`,
		},
		StepID:   "ssh-template-apply",
		StepType: "template",
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
				PlanResult: pluginapi.PlanResult{
					Summary: `template step: no rewrite required for "/etc/example.conf" (content and mode already match)`,
				},
				StepID:   "ssh-template-apply",
				StepType: "template",
			},
		}

		out := renderCompactPlan(p, steps, "host-1")
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
					PlanResult: pluginapi.PlanResult{
						Summary:         `template step: render "src" to "/etc/example.conf" (mode 0644)`,
						OperatorSummary: `Write rendered configuration from "src" to "/etc/example.conf" with mode 0644`,
					},
				},
				want: `Write rendered configuration from "src" to "/etc/example.conf" with mode 0644`,
			},
			{
				name: "fallback summary",
				step: StepPlan{
					PlanResult: pluginapi.PlanResult{
						Summary: `service step: enable ssh at boot`,
					},
				},
				want: `Enable ssh at boot`,
			},
			{
				name: "plain summary passthrough",
				step: StepPlan{
					PlanResult: pluginapi.PlanResult{
						Summary: `plain summary`,
					},
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

		counts := dispositionCounts([]StepPlan{
			{PlanResult: pluginapi.PlanResult{WillChange: false}},
			{PlanResult: pluginapi.PlanResult{WillChange: true}},
			{PlanResult: pluginapi.PlanResult{WillChange: true, Highlights: []string{logger.ColorRed + "failed to preview upgrades" + logger.ColorReset}}},
		})
		if counts[dispositionAligned] != 1 || counts[dispositionPlanned] != 1 || counts[dispositionAttention] != 1 {
			t.Fatalf("unexpected disposition counts: %#v", counts)
		}
		if stepDispositionFor(StepPlan{PlanResult: pluginapi.PlanResult{WillChange: false}}) != dispositionAligned {
			t.Fatal("expected aligned step")
		}
		if stepDispositionFor(StepPlan{PlanResult: pluginapi.PlanResult{WillChange: true}}) != dispositionPlanned {
			t.Fatal("expected changed step to be planned")
		}
		if stepDispositionFor(StepPlan{PlanResult: pluginapi.PlanResult{WillChange: true, Highlights: []string{logger.ColorRed + "failed to preview upgrades" + logger.ColorReset}}}) != dispositionAttention {
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
		ID:          "starter-secure-ubuntu-24.04-lts",
		DisplayName: "Starter Secure Ubuntu",
		Version:     "1.2.3",
		OS:          profile.OSInfo{Family: "ubuntu", Version: "24.04"},
	}
	steps := []StepPlan{
		{
			PlanResult: pluginapi.PlanResult{
				Summary:         `template step: no rewrite required for "/etc/ssh/sshd_config"`,
				OperatorSummary: `"/etc/ssh/sshd_config" already matches the desired content and mode`,
				Details:         []string{logger.ColorGreen + "already present" + logger.ColorReset},
			},
			StepID:   "ssh-template-apply",
			StepType: "template",
		},
		{
			PlanResult: pluginapi.PlanResult{
				WillChange:      true,
				Summary:         `firewall step: configure default deny`,
				OperatorSummary: `Configure nftables default deny policy`,
				Diff:            []string{`chain input policy: accept -> drop`},
				Highlights:      []string{logger.ColorRed + `nftables.conf include "/etc/nftables.d/*.nft" is missing` + logger.ColorReset},
			},
			StepID:   "firewall-default-deny",
			StepType: "firewall",
		},
	}

	report := buildPlanReport(p, steps, "./profiles/starter-secure-ubuntu-24.04-lts", "host-1", "/tmp/dev-overrides.json")
	if report.Kind != "hardline_plan" || report.Summary.StepsInspected != 2 {
		t.Fatalf("unexpected report summary %+v", report.Summary)
	}
	if report.Summary.AlreadyAligned != 1 || report.Summary.NeedsAttention != 1 {
		t.Fatalf("unexpected report counts %+v", report.Summary)
	}
	if report.NextSteps.ApplyCommand != `hardline apply ./profiles/starter-secure-ubuntu-24.04-lts --host host-1 --overrides-file "/tmp/dev-overrides.json"` {
		t.Fatalf("unexpected apply command %q", report.NextSteps.ApplyCommand)
	}
	if report.NextSteps.RollbackCommand != `hardline rollback ./profiles/starter-secure-ubuntu-24.04-lts --host host-1` {
		t.Fatalf("unexpected rollback command %q", report.NextSteps.RollbackCommand)
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
	if got := applyCommand("profile-1", "", ""); got != "hardline apply profile-1" {
		t.Fatalf("unexpected apply command without host %q", got)
	}
	if got := applyCommand("profile-1", "host-1", ""); got != "hardline apply profile-1 --host host-1" {
		t.Fatalf("unexpected apply command with host %q", got)
	}
	if got := applyCommand("profile-1", "host-1", "/tmp/dev-overrides.json"); got != `hardline apply profile-1 --host host-1 --overrides-file "/tmp/dev-overrides.json"` {
		t.Fatalf("unexpected apply command with overrides file %q", got)
	}
	if got := rollbackCommand("profile-1", ""); got != "hardline rollback profile-1" {
		t.Fatalf("unexpected rollback command without host %q", got)
	}
	if got := rollbackCommand("profile-1", "host-1"); got != "hardline rollback profile-1 --host host-1" {
		t.Fatalf("unexpected rollback command with host %q", got)
	}
	if got := displayTargetHost(""); got != "(host not set)" {
		t.Fatalf("unexpected display target host %q", got)
	}
}

func TestPlan_WithStubbedDependencies(t *testing.T) {
	prevLoad := loadPlanProfile
	prevVer := planVersionCmd
	prevCmp := planCompareSemVer
	prevSSH := newPlanSSHClient
	prevRunProfile := runPlanForProfile
	prevEnsurePlugins := ensurePlanPlugins
	defer func() {
		loadPlanProfile = prevLoad
		planVersionCmd = prevVer
		planCompareSemVer = prevCmp
		newPlanSSHClient = prevSSH
		runPlanForProfile = prevRunProfile
		ensurePlanPlugins = prevEnsurePlugins
	}()

	goodProfile := mustLoadFixtureProfile(t, profileFixture{
		ID:          "ok",
		DisplayName: "OK",
		MinHardline: "0.1.0",
		Schema:      1,
	})

	loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	newPlanSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	runPlanForProfile = func(*remote.Client, *profile.Profile, planRunOptions) error { return nil }

	t.Run("profile load error", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) { return nil, errors.New("load fail") }
		err := Plan(cli.Command{Profile: "x", Debug: false})
		if err == nil || !strings.Contains(err.Error(), "profile load failed") {
			t.Fatalf("expected profile load error, got %v", err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("report output config error", func(t *testing.T) {
		err := Plan(cli.Command{Profile: "x", Debug: true, ReportFormat: "json"})
		if err == nil || !strings.Contains(err.Error(), "plan output configuration failed") {
			t.Fatalf("expected report config error, got %v", err)
		}
	})

	t.Run("version command error", func(t *testing.T) {
		planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{}, 0, errors.New("bad version") }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "hardline version check failed") {
			t.Fatalf("expected version command error, got %v", err)
		}
		planVersionCmd = func() (cli.SemVer, int, error) { return cli.SemVer{Major: 1, Minor: 0, Patch: 0}, 1, nil }
	})

	t.Run("compare error", func(t *testing.T) {
		planCompareSemVer = func(_, _ string) (int, error) { return 0, errors.New("bad semver") }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "invalid profile.min_hardline value") {
			t.Fatalf("expected compare error, got %v", err)
		}
		planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	})

	t.Run("version too old", func(t *testing.T) {
		planCompareSemVer = func(_, _ string) (int, error) { return -1, nil }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "too old") {
			t.Fatalf("expected version too old error, got %v", err)
		}
		planCompareSemVer = func(_, _ string) (int, error) { return 1, nil }
	})

	t.Run("schema too new", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "0.1.0", ProfileSchema: 2}, nil
		}
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "profile schema") {
			t.Fatalf("expected schema too new error, got %v", err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("affirm failure", func(t *testing.T) {
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return &profile.Profile{MinHardline: "0.1.0", ProfileSchema: 1}, nil
		}
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "profile validation failed") {
			t.Fatalf("expected affirm error, got %v", err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("required plugin missing", func(t *testing.T) {
		ensurePlanPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return errors.New("required plugin missing") }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "required plugin validation failed") {
			t.Fatalf("expected required plugin error, got %v", err)
		}
		ensurePlanPlugins = pluginapi.EnsureProfilePlugins
	})

	t.Run("override validation failure", func(t *testing.T) {
		overridesDir := t.TempDir()
		overridesPath := filepath.Join(overridesDir, "overrides.json")
		if err := os.WriteFile(overridesPath, []byte(`{"smtp_port": 25}`), 0o644); err != nil {
			t.Fatal(err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return mustLoadFixtureProfile(t, profileFixture{
				ID:               "ok",
				DisplayName:      "OK",
				MinHardline:      "0.1.0",
				Schema:           1,
				AllowedOverrides: []string{"ssh_port"},
			}), nil
		}
		err := Plan(cli.Command{
			Profile:       "x",
			Debug:         true,
			OverridesFile: overridesPath,
		})
		if err == nil || !strings.Contains(err.Error(), "profile override validation failed") {
			t.Fatalf("expected override validation error, got %v", err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
	})

	t.Run("connect failure", func(t *testing.T) {
		newPlanSSHClient = func(connection.Config) (*remote.Client, error) { return nil, errors.New("connect fail") }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "connect failed") {
			t.Fatalf("expected connect failure, got %v", err)
		}
		newPlanSSHClient = func(connection.Config) (*remote.Client, error) { return nil, nil }
	})

	t.Run("plan profile failure", func(t *testing.T) {
		runPlanForProfile = func(*remote.Client, *profile.Profile, planRunOptions) error { return errors.New("plan fail") }
		err := Plan(cli.Command{Profile: "x", Debug: true})
		if err == nil || !strings.Contains(err.Error(), "plan fail") {
			t.Fatalf("expected plan profile failure, got %v", err)
		}
		runPlanForProfile = func(*remote.Client, *profile.Profile, planRunOptions) error { return nil }
	})

	t.Run("success", func(t *testing.T) {
		if err := Plan(cli.Command{Profile: "x", Host: "h1", User: "u1", KeyPath: "k1", Debug: false}); err != nil {
			t.Fatalf("did not expect error on success path: %v", err)
		}
	})

	t.Run("success with overrides", func(t *testing.T) {
		overridesDir := t.TempDir()
		overridesPath := filepath.Join(overridesDir, "overrides.json")
		if err := os.WriteFile(overridesPath, []byte(`{"ssh_port": 2222}`), 0o644); err != nil {
			t.Fatal(err)
		}
		loadPlanProfile = func(string) (*profile.Profile, error) {
			return mustLoadFixtureProfile(t, profileFixture{
				ID:               "ok",
				DisplayName:      "OK",
				MinHardline:      "0.1.0",
				Schema:           1,
				AllowedOverrides: []string{"ssh_port"},
			}), nil
		}
		runPlanForProfile = func(_ *remote.Client, p *profile.Profile, options planRunOptions) error {
			if string(p.RuntimeOverrides()["ssh_port"]) != "2222" {
				t.Fatalf("expected runtime overrides on profile, got %+v", p.RuntimeOverrides())
			}
			if options.OverridesFile != overridesPath {
				t.Fatalf("expected overrides file in plan options, got %q", options.OverridesFile)
			}
			return nil
		}

		if err := Plan(cli.Command{
			Profile:       "x",
			Host:          "h1",
			User:          "u1",
			KeyPath:       "k1",
			Debug:         false,
			OverridesFile: overridesPath,
		}); err != nil {
			t.Fatalf("did not expect error on success path with overrides: %v", err)
		}

		loadPlanProfile = func(string) (*profile.Profile, error) { return goodProfile, nil }
		runPlanForProfile = func(*remote.Client, *profile.Profile, planRunOptions) error { return nil }
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

type profileFixture struct {
	ID               string
	DisplayName      string
	MinHardline      string
	Schema           int
	AllowedOverrides []string
}

func writeProfileFixture(t *testing.T, f profileFixture) string {
	t.Helper()
	dir := t.TempDir()
	allowedOverrides := f.AllowedOverrides
	if allowedOverrides == nil {
		allowedOverrides = []string{}
	}
	allowedOverridesJSON, err := json.Marshal(allowedOverrides)
	if err != nil {
		t.Fatalf("marshal allowed_overrides: %v", err)
	}
	body := `{
  "id": "` + f.ID + `",
  "display_name": "` + f.DisplayName + `",
  "version": "1.0.0",
  "os": {"family":"ubuntu","version":"24.04","variant":"lts"},
  "profile_schema": ` + strconv.Itoa(f.Schema) + `,
  "min_hardline": "` + f.MinHardline + `",
  "actions": [],
  "templates": [],
  "allowed_overrides": ` + string(allowedOverridesJSON) + `
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
