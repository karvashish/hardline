package plan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/pkg/profile"
	"gopkg.in/yaml.v3"
)

type planFileReport struct {
	Kind           string            `json:"kind" yaml:"kind"`
	Profile        planFileProfile   `json:"profile" yaml:"profile"`
	Target         planFileTarget    `json:"target" yaml:"target"`
	Summary        planFileSummary   `json:"summary" yaml:"summary"`
	ChangesPlanned []string          `json:"changes_planned,omitempty" yaml:"changes_planned,omitempty"`
	NeedsAttention []string          `json:"needs_attention,omitempty" yaml:"needs_attention,omitempty"`
	Steps          []planFileStep    `json:"steps" yaml:"steps"`
	NextSteps      planFileNextSteps `json:"next_steps" yaml:"next_steps"`
}

type planFileProfile struct {
	ID          string `json:"id" yaml:"id"`
	DisplayName string `json:"display_name" yaml:"display_name"`
	Version     string `json:"version" yaml:"version"`
}

type planFileTarget struct {
	Host      string `json:"host" yaml:"host"`
	OSFamily  string `json:"os_family" yaml:"os_family"`
	OSVersion string `json:"os_version" yaml:"os_version"`
}

type planFileSummary struct {
	StepsInspected    int               `json:"steps_inspected" yaml:"steps_inspected"`
	AlreadyAligned    int               `json:"already_aligned" yaml:"already_aligned"`
	ChangesPlanned    int               `json:"changes_planned" yaml:"changes_planned"`
	NeedsAttention    int               `json:"needs_attention" yaml:"needs_attention"`
	OverallRisk       string            `json:"overall_risk" yaml:"overall_risk"`
	RiskBreakdown     planRiskBreakdown `json:"risk_breakdown" yaml:"risk_breakdown"`
	RollbackAvailable bool              `json:"rollback_available" yaml:"rollback_available"`
}

type planRiskBreakdown struct {
	Critical int `json:"critical" yaml:"critical"`
	High     int `json:"high" yaml:"high"`
	Medium   int `json:"medium" yaml:"medium"`
	Low      int `json:"low" yaml:"low"`
	Unknown  int `json:"unknown" yaml:"unknown"`
}

type planFileStep struct {
	ID              string   `json:"id" yaml:"id"`
	Type            string   `json:"type" yaml:"type"`
	Status          string   `json:"status" yaml:"status"`
	Severity        string   `json:"severity" yaml:"severity"`
	RiskClass       string   `json:"risk_class,omitempty" yaml:"risk_class,omitempty"`
	Summary         string   `json:"summary" yaml:"summary"`
	OperatorSummary string   `json:"operator_summary" yaml:"operator_summary"`
	Details         []string `json:"details,omitempty" yaml:"details,omitempty"`
	Diff            []string `json:"diff,omitempty" yaml:"diff,omitempty"`
	Highlights      []string `json:"highlights,omitempty" yaml:"highlights,omitempty"`
	Noop            int      `json:"noop" yaml:"noop"`
}

type planFileNextSteps struct {
	ApplyCommand    string `json:"apply_command" yaml:"apply_command"`
	RollbackCommand string `json:"rollback_command" yaml:"rollback_command"`
}

func validatePlanOutputs(c cli.Command) error {
	if strings.TrimSpace(c.ReportFormat) != "" && strings.TrimSpace(c.ReportFile) == "" {
		return fmt.Errorf("--report-format requires --report-file")
	}
	if strings.TrimSpace(c.ReportFile) == "" {
		return nil
	}
	_, err := resolveReportFormat(c.ReportFile, c.ReportFormat)
	return err
}

func writePlanArtifacts(profile profile.Profile, steps []StepPlan, options planRunOptions) (string, error) {
	if strings.TrimSpace(options.ReportFile) == "" {
		return "", nil
	}

	format, err := resolveReportFormat(options.ReportFile, options.ReportFormat)
	if err != nil {
		return "", err
	}

	report := buildPlanReport(profile, steps, options.Host)
	body, err := renderPlanArtifact(report, format)
	if err != nil {
		return "", err
	}
	if err := writePlanArtifactFile(options.ReportFile, body); err != nil {
		return "", err
	}
	return format, nil
}

func resolveReportFormat(path string, explicit string) (string, error) {
	explicit = strings.TrimSpace(explicit)
	if explicit != "" {
		format := normalizeReportFormat(explicit)
		if format == "" {
			return "", fmt.Errorf("unsupported report format %q; use json, yaml, or md", explicit)
		}
		return format, nil
	}

	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".json":
		return "json", nil
	case ".yaml", ".yml":
		return "yaml", nil
	case ".md", ".markdown":
		return "md", nil
	default:
		return "", fmt.Errorf("unsupported report format for %q; use --report-format json|yaml|md or a .json/.yaml/.yml/.md file extension", path)
	}
}

func normalizeReportFormat(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "":
		return ""
	case "json":
		return "json"
	case "yaml", "yml":
		return "yaml"
	case "md", "markdown":
		return "md"
	default:
		return ""
	}
}

func renderPlanArtifact(report planFileReport, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "yaml":
		return yaml.Marshal(report)
	case "md":
		return []byte(renderPlanMarkdown(report)), nil
	default:
		return nil, fmt.Errorf("unsupported report format %q", format)
	}
}

func writePlanArtifactFile(path string, body []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, body, 0o644)
}

func buildPlanReport(profile profile.Profile, steps []StepPlan, host string) planFileReport {
	counts := dispositionCounts(steps)
	report := planFileReport{
		Kind: "hardline_plan",
		Profile: planFileProfile{
			ID:          profile.ID,
			DisplayName: profile.DisplayName,
			Version:     profile.Version,
		},
		Target: planFileTarget{
			Host:      strings.TrimSpace(host),
			OSFamily:  profile.OS.Family,
			OSVersion: profile.OS.Version,
		},
		Summary: planFileSummary{
			StepsInspected:    len(steps),
			AlreadyAligned:    counts[dispositionAligned],
			ChangesPlanned:    counts[dispositionPlanned],
			NeedsAttention:    counts[dispositionAttention],
			OverallRisk:       strings.ToLower(overallSeverity(steps)),
			RiskBreakdown:     severityBreakdownCounts(steps),
			RollbackAvailable: true,
		},
		ChangesPlanned: collectPlannedChanges(steps),
		NeedsAttention: collectAttentionNotes(steps),
		Steps:          make([]planFileStep, 0, len(steps)),
		NextSteps: planFileNextSteps{
			ApplyCommand:    applyCommand(profile.ID, host),
			RollbackCommand: rollbackCommand(host),
		},
	}

	for _, step := range steps {
		report.Steps = append(report.Steps, planFileStep{
			ID:              step.StepID,
			Type:            step.StepType,
			Status:          dispositionCode(stepDispositionFor(step)),
			Severity:        normalizedSeverity(step.Severity),
			RiskClass:       strings.TrimSpace(step.RiskClass),
			Summary:         normalizeLogText(step.Summary),
			OperatorSummary: compactOperatorSummary(step),
			Details:         normalizedReportLines(step.Details),
			Diff:            normalizedReportLines(step.Diff),
			Highlights:      normalizedReportLines(step.Highlights),
			Noop:            step.Noop,
		})
	}

	return report
}

func renderPlanMarkdown(report planFileReport) string {
	var b strings.Builder

	fmt.Fprintf(&b, "# Hardline Plan Report\n\n")
	fmt.Fprintf(&b, "## Profile\n\n")
	fmt.Fprintf(&b, "- Profile: %s\n", markdownValue(report.Profile.DisplayName))
	fmt.Fprintf(&b, "- Profile ID: `%s`\n", report.Profile.ID)
	fmt.Fprintf(&b, "- Version: `%s`\n", report.Profile.Version)
	fmt.Fprintf(&b, "- Target: `%s` (%s %s)\n\n",
		displayTargetHost(report.Target.Host), report.Target.OSFamily, report.Target.OSVersion)

	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Steps inspected: %d\n", report.Summary.StepsInspected)
	fmt.Fprintf(&b, "- Already aligned: %d\n", report.Summary.AlreadyAligned)
	fmt.Fprintf(&b, "- Changes planned: %d\n", report.Summary.ChangesPlanned)
	fmt.Fprintf(&b, "- Needs attention: %d\n", report.Summary.NeedsAttention)
	fmt.Fprintf(&b, "- Overall risk: %s\n", report.Summary.OverallRisk)
	fmt.Fprintf(&b, "- Risk breakdown: critical %d, high %d, medium %d, low %d, unknown %d\n", report.Summary.RiskBreakdown.Critical, report.Summary.RiskBreakdown.High, report.Summary.RiskBreakdown.Medium, report.Summary.RiskBreakdown.Low, report.Summary.RiskBreakdown.Unknown)
	fmt.Fprintf(&b, "- Rollback available: %t\n\n", report.Summary.RollbackAvailable)

	if len(report.ChangesPlanned) > 0 {
		fmt.Fprintf(&b, "## Changes Planned\n\n")
		for _, change := range report.ChangesPlanned {
			fmt.Fprintf(&b, "- %s\n", markdownValue(change))
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(report.NeedsAttention) > 0 {
		fmt.Fprintf(&b, "## Needs Attention\n\n")
		for _, note := range report.NeedsAttention {
			fmt.Fprintf(&b, "- %s\n", markdownValue(note))
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Steps\n\n")
	for _, step := range report.Steps {
		fmt.Fprintf(&b, "### %s (`%s`)\n\n", markdownValue(step.ID), step.Type)
		fmt.Fprintf(&b, "- Status: %s\n", markdownValue(statusTitle(step.Status)))
		fmt.Fprintf(&b, "- Severity: %s\n", markdownValue(step.Severity))
		if step.RiskClass != "" {
			fmt.Fprintf(&b, "- Risk class: %s\n", markdownValue(step.RiskClass))
		}
		fmt.Fprintf(&b, "- Operator summary: %s\n", markdownValue(step.OperatorSummary))
		fmt.Fprintf(&b, "- Summary: %s\n", markdownValue(step.Summary))
		if len(step.Details) > 0 {
			fmt.Fprintf(&b, "- Details:\n")
			for _, detail := range step.Details {
				fmt.Fprintf(&b, "  - %s\n", markdownValue(detail))
			}
		}
		if len(step.Diff) > 0 {
			fmt.Fprintf(&b, "- Final state diff:\n")
			for _, line := range step.Diff {
				fmt.Fprintf(&b, "  - %s\n", markdownValue(line))
			}
		}
		if len(step.Highlights) > 0 {
			fmt.Fprintf(&b, "- Highlights:\n")
			for _, highlight := range step.Highlights {
				fmt.Fprintf(&b, "  - %s\n", markdownValue(highlight))
			}
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Next Steps\n\n")
	fmt.Fprintf(&b, "- Apply changes: `%s`\n", report.NextSteps.ApplyCommand)
	fmt.Fprintf(&b, "- Rollback last run: `%s`\n", report.NextSteps.RollbackCommand)
	fmt.Fprintf(&b, "- No changes have been made yet.\n")

	return b.String()
}

func severityBreakdownCounts(steps []StepPlan) planRiskBreakdown {
	var counts planRiskBreakdown

	for _, step := range steps {
		switch normalizedSeverity(step.Severity) {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		default:
			counts.Unknown++
		}
	}

	return counts
}

func normalizedSeverity(severity string) string {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev == "" {
		return "low"
	}
	switch sev {
	case "critical", "high", "medium", "low":
		return sev
	default:
		return "unknown"
	}
}

func normalizedReportLines(lines []string) []string {
	var cleanLines []string
	seen := make(map[string]struct{})
	for _, line := range lines {
		clean := normalizeLogText(line)
		if clean == "" {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		cleanLines = append(cleanLines, clean)
	}
	return cleanLines
}

func dispositionCode(disposition stepDisposition) string {
	switch disposition {
	case dispositionAligned:
		return "already_aligned"
	case dispositionAttention:
		return "needs_attention"
	default:
		return "change_planned"
	}
}

func statusTitle(status string) string {
	switch status {
	case "already_aligned":
		return "Already aligned"
	case "needs_attention":
		return "Needs attention"
	default:
		return "Change planned"
	}
}

func displayTargetHost(host string) string {
	if strings.TrimSpace(host) == "" {
		return "(host not set)"
	}
	return strings.TrimSpace(host)
}

func applyCommand(profileID string, host string) string {
	cmd := "hardline apply " + profileID
	if strings.TrimSpace(host) != "" {
		cmd += " --host " + strings.TrimSpace(host)
	}
	return cmd
}

func rollbackCommand(host string) string {
	cmd := "hardline rollback last"
	if strings.TrimSpace(host) != "" {
		cmd += " --host " + strings.TrimSpace(host)
	}
	return cmd
}

func markdownValue(text string) string {
	return strings.ReplaceAll(text, "\n", " ")
}
