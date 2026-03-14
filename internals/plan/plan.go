package plan

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var (
	loadPlanProfile   = profile.Load
	planVersionCmd    = cli.VersionCmd
	planCompareSemVer = cli.CompareSemVer
	newPlanSSHClient  = connection.NewSSHClient
	runPlanForProfile = planProfile
	runPlanStep       = planStep
	ensurePlanPlugins = registry.EnsureProfilePlugins
	exitPlan          = os.Exit
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type planRunOptions struct {
	Host         string
	ReportFile   string
	ReportFormat string
}

type stepDisposition string

const (
	dispositionAligned   stepDisposition = "aligned"
	dispositionPlanned   stepDisposition = "planned"
	dispositionAttention stepDisposition = "attention"
)

func Plan(c cli.Command) {
	/*
		1. Load and validate a profile (and its actions/templates).
		2. Contact the target server and inspect current state (read-only).
		3. Generate a logical diff of what `apply` would do`.
		4. Compute per-step risk scores and priority order.
		5. Derive mitigations and rollback strategies for each step and use them to reduce risk.
		6. Aggregate a final run-level risk and present it clearly to the user.
	*/
	if !c.Debug {
		target := displayTargetHost(c.Host)
		logger.Infof("Planning %s on %s\n", c.Profile, target)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	if err := validatePlanOutputs(c); err != nil {
		logger.Errorf("plan output configuration failed: %v\n", err)
		exitPlan(1)
	}

	p, err := loadPlanProfile(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		exitPlan(1)
	}

	logger.Debugf("profile loaded, starting validation\n")

	ver, schemaVer, err := planVersionCmd()
	if err != nil {
		logger.Errorf("hardline version check failed: %v\n", err)
		exitPlan(1)
	}

	cmp, err := planCompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Errorf("invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		exitPlan(1)
	}

	if cmp < 0 {
		logger.Errorf("hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline)
		exitPlan(1)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf("profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer)
		exitPlan(1)
	}

	if err := p.Affirm(); err != nil {
		logger.Errorf("profile validation failed: %v\n", err)
		exitPlan(1)
	}
	if err := ensurePlanPlugins(p); err != nil {
		logger.Errorf("required plugin validation failed: %v\n", err)
		exitPlan(1)
	}

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := newPlanSSHClient(*config)
	if err != nil {
		logger.Errorf("connect failed: %v\n", err)
		exitPlan(1)
	}
	if sshClient != nil {
		defer sshClient.Close()
	}

	logger.Debugf("ssh connection established\n")

	if err := runPlanForProfile(sshClient, p, planRunOptions{
		Host:         c.Host,
		ReportFile:   c.ReportFile,
		ReportFormat: c.ReportFormat,
	}); err != nil {
		logger.Errorf("plan failed: %v\n", err)
		exitPlan(1)
	}

	logger.Debugf("plan completed\n")

	// TODO:
	// 4. Compute per-step risk scores and priority order.
	// 5. Derive mitigations and rollback strategies.
	// 6. Aggregate final run-level risk and print report.
}

func planProfile(client *ssh.Client, p *profile.Profile, options planRunOptions) error {
	logger.Debugf("planProfile: %d action files\n", len(p.ActionFiles))

	var plans []StepPlan
	totalSteps := countPlanSteps(p)
	currentStep := 0

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			currentStep++
			var stop func()
			if !logger.DebugMode() {
				logger.Infof("Inspecting %02d/%02d %s [%s] ", currentStep, totalSteps, step.ID, step.PluginName())
				stop = utils.Throbber()
			}
			logger.Debugf("planStep: id=%q type=%q\n", step.ID, step.PluginName())

			sp, err := runPlanStep(client, p, step)
			if stop != nil {
				stop()
			}

			if err != nil {
				if !logger.DebugMode() {
					logger.Infof("\n")
				}
				return err
			}

			plans = append(plans, sp)

			if !logger.DebugMode() {
				logger.Infof("\n%s", renderCompactStepResult(sp))
			}
		}
	}
	printPlan(*p, plans, options.Host)
	reportFormat, err := writePlanArtifacts(*p, plans, options)
	if err != nil {
		return err
	}
	if strings.TrimSpace(options.ReportFile) != "" {
		logger.Infof("Report saved to %s (%s)\n", options.ReportFile, strings.ToUpper(reportFormat))
	}

	return nil
}

func printPlan(profile profile.Profile, steps []StepPlan, hostname string) {
	logger.Infof("%s", renderPlan(profile, steps, hostname, logger.DebugMode()))
}

func renderPlan(profile profile.Profile, steps []StepPlan, hostname string, debug bool) string {
	if debug {
		return renderDetailedPlan(profile, steps, hostname)
	}
	return renderCompactPlan(profile, steps, hostname)
}

func renderDetailedPlan(profile profile.Profile, steps []StepPlan, hostname string) string {
	var b strings.Builder

	writePlanHeader(&b, profile, hostname)
	writePlanSummary(&b, steps)

	fmt.Fprintf(&b, "%sACTIONS%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("=", 60))

	for _, s := range steps {
		fmt.Fprintf(&b, "\n%s[%s] (%s)%s\n",
			logger.ColorWhite+logger.ColorBold, s.StepID, s.StepType, logger.ColorReset)
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 60))
		fmt.Fprintf(&b, "%sSummary%s : %s\n", logger.ColorBold, logger.ColorReset, s.Summary)
		fmt.Fprintf(&b, "%sRisk%s    : %s\n", logger.ColorBold, logger.ColorReset, s.RiskClass)
		fmt.Fprintf(&b, "%sSeverity%s: %s\n", logger.ColorBold, logger.ColorReset, severityColor(s.Severity))
		fmt.Fprintf(&b, "%sStatus%s  : %s\n", logger.ColorBold, logger.ColorReset, upperFirst(dispositionText(stepDispositionFor(s))))

		if len(s.Details) > 0 {
			fmt.Fprintf(&b, "%sDetails%s:\n", logger.ColorBold, logger.ColorReset)
			for _, line := range s.Details {
				fmt.Fprintf(&b, "  - %s\n", line)
			}
		}
		if diff := normalizedReportLines(s.Diff); len(diff) > 0 {
			fmt.Fprintf(&b, "%sFinal State Diff%s:\n", logger.ColorBold, logger.ColorReset)
			for _, line := range diff {
				fmt.Fprintf(&b, "  - %s\n", line)
			}
		}
	}

	writePlanFooter(&b, profile, hostname)
	return b.String()
}

func renderCompactPlan(profile profile.Profile, steps []StepPlan, hostname string) string {
	var b strings.Builder

	writePlanHeader(&b, profile, hostname)
	writePlanSummary(&b, steps)

	planned := collectPlannedChanges(steps)
	if len(planned) > 0 {
		fmt.Fprintf(&b, "%sCHANGES PLANNED%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 60))
		for _, change := range planned {
			fmt.Fprintf(&b, "- %s\n", change)
		}
		fmt.Fprintf(&b, "\n")
	}

	keyFindings := collectAttentionNotes(steps)
	if len(keyFindings) > 0 {
		fmt.Fprintf(&b, "%sNEEDS ATTENTION%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
		fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 60))
		for _, note := range keyFindings {
			fmt.Fprintf(&b, "- %s\n", note)
		}
		fmt.Fprintf(&b, "\n")
	}

	writePlanFooter(&b, profile, hostname)
	return b.String()
}

func writePlanHeader(b *strings.Builder, profile profile.Profile, hostname string) {
	fmt.Fprintf(b, "\n%sHARDLINE PLAN%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	fmt.Fprintf(b, "%sProfile%s : %s\n", logger.ColorBold, logger.ColorReset, profile.DisplayName)
	fmt.Fprintf(b, "%sVersion%s : %s\n", logger.ColorBold, logger.ColorReset, profile.Version)
	fmt.Fprintf(b, "%sTarget%s  : %s (%s %s)\n",
		logger.ColorBold, logger.ColorReset, displayTargetHost(hostname), profile.OS.Family, profile.OS.Version)
	fmt.Fprintf(b, "%s\n\n", strings.Repeat("-", 60))
}

func writePlanFooter(b *strings.Builder, profile profile.Profile, hostname string) {
	fmt.Fprintf(b, "%sNEXT STEPS%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	fmt.Fprintf(b, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(b, "Apply changes:\n  %s\n\n",
		logger.ColorBold+applyCommand(profile.ID, hostname)+logger.ColorReset)
	fmt.Fprintf(b, "Rollback last run:\n  %s\n\n",
		logger.ColorBold+rollbackCommand(hostname)+logger.ColorReset)
	fmt.Fprintf(b, "%sPlan complete. No changes have been made.%s\n",
		logger.ColorGreen, logger.ColorReset)
}

func writePlanSummary(b *strings.Builder, steps []StepPlan) {
	counts := dispositionCounts(steps)

	fmt.Fprintf(b, "%sSUMMARY%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	fmt.Fprintf(b, "%s\n", strings.Repeat("-", 60))
	fmt.Fprintf(b, "%sSteps inspected%s : %s%d%s\n",
		logger.ColorBold, logger.ColorReset, logger.ColorGreen, len(steps), logger.ColorReset)
	fmt.Fprintf(b, "%sAlready aligned%s : %s%d%s\n",
		logger.ColorBold, logger.ColorReset, logger.ColorGreen, counts[dispositionAligned], logger.ColorReset)
	fmt.Fprintf(b, "%sChanges planned%s : %s%d%s\n",
		logger.ColorBold, logger.ColorReset, logger.ColorBlue, counts[dispositionPlanned], logger.ColorReset)
	fmt.Fprintf(b, "%sNeeds attention%s : %s%d%s\n",
		logger.ColorBold, logger.ColorReset, logger.ColorRed, counts[dispositionAttention], logger.ColorReset)

	overall := overallSeverity(steps)
	fmt.Fprintf(b, "%sOverall risk%s    : %s\n",
		logger.ColorBold, logger.ColorReset, severityColor(overall))
	fmt.Fprintf(b, "%sRisk breakdown%s  : %s\n",
		logger.ColorBold, logger.ColorReset, renderSeverityBreakdown(steps))
	fmt.Fprintf(b, "%sRollback%s        : %sAVAILABLE%s\n\n",
		logger.ColorBold, logger.ColorReset, logger.ColorGreen, logger.ColorReset)
	fmt.Fprintf(b, "%sNo changes will be made until 'hardline apply' is executed.%s\n\n",
		logger.ColorDim, logger.ColorReset)
}

func renderCompactStepResult(step StepPlan) string {
	var b strings.Builder

	disposition := stepDispositionFor(step)
	fmt.Fprintf(&b, "  %s%-15s%s %s",
		dispositionColor(disposition), strings.ToUpper(dispositionText(disposition)), logger.ColorReset,
		severityColor(step.Severity))
	if risk := strings.TrimSpace(step.RiskClass); risk != "" {
		fmt.Fprintf(&b, "/%s", risk)
	}
	fmt.Fprintf(&b, " %s\n", compactOperatorSummary(step))

	for _, line := range previewPlanLines(step.Diff, 2) {
		fmt.Fprintf(&b, "    %schange%s: %s\n", logger.ColorBlue, logger.ColorReset, line)
	}
	for _, note := range normalizedHighlights(step.Highlights) {
		fmt.Fprintf(&b, "    %snote%s: %s\n", logger.ColorYellow, logger.ColorReset, note)
	}

	return b.String()
}

func compactStepSummary(summary string) string {
	clean := normalizeLogText(summary)
	if idx := strings.Index(clean, ": "); idx >= 0 {
		return strings.TrimSpace(clean[idx+2:])
	}
	return clean
}

func compactOperatorSummary(step StepPlan) string {
	if summary := normalizeLogText(step.OperatorSummary); summary != "" {
		return summary
	}
	return upperFirst(compactStepSummary(step.Summary))
}

func collectPlannedChanges(steps []StepPlan) []string {
	var changes []string
	seen := make(map[string]struct{})

	for _, step := range steps {
		if stepDispositionFor(step) != dispositionPlanned {
			continue
		}
		change := fmt.Sprintf("%s: %s", step.StepID, compactOperatorSummary(step))
		if _, ok := seen[change]; ok {
			continue
		}
		seen[change] = struct{}{}
		changes = append(changes, change)
	}

	return changes
}

func collectAttentionNotes(steps []StepPlan) []string {
	var notes []string
	seen := make(map[string]struct{})

	for _, step := range steps {
		if stepDispositionFor(step) != dispositionAttention {
			continue
		}
		for _, detail := range normalizedHighlights(step.Highlights) {
			note := fmt.Sprintf("%s: %s", step.StepID, detail)
			if _, ok := seen[note]; ok {
				continue
			}
			seen[note] = struct{}{}
			notes = append(notes, note)
		}
	}

	return notes
}

func normalizedHighlights(highlights []string) []string {
	notes := normalizedReportLines(highlights)
	if len(notes) > 2 {
		return notes[:2]
	}
	return notes
}

func previewPlanLines(lines []string, limit int) []string {
	clean := normalizedReportLines(lines)
	if limit <= 0 || len(clean) <= limit {
		return clean
	}
	return clean[:limit]
}

func normalizeLogText(text string) string {
	clean := ansiPattern.ReplaceAllString(text, "")
	return strings.Join(strings.Fields(clean), " ")
}

func renderSeverityBreakdown(steps []StepPlan) string {
	counts := severityBreakdownCounts(steps)
	var parts []string
	if counts.Critical > 0 {
		parts = append(parts, fmt.Sprintf("critical %d", counts.Critical))
	}
	if counts.High > 0 {
		parts = append(parts, fmt.Sprintf("high %d", counts.High))
	}
	if counts.Medium > 0 {
		parts = append(parts, fmt.Sprintf("medium %d", counts.Medium))
	}
	if counts.Low > 0 {
		parts = append(parts, fmt.Sprintf("low %d", counts.Low))
	}
	if counts.Unknown > 0 {
		parts = append(parts, fmt.Sprintf("unknown %d", counts.Unknown))
	}
	if len(parts) == 0 {
		return "low 0"
	}
	return strings.Join(parts, ", ")
}

func dispositionCounts(steps []StepPlan) map[stepDisposition]int {
	counts := map[stepDisposition]int{
		dispositionAligned:   0,
		dispositionPlanned:   0,
		dispositionAttention: 0,
	}
	for _, step := range steps {
		counts[stepDispositionFor(step)]++
	}
	return counts
}

func stepDispositionFor(step StepPlan) stepDisposition {
	if len(normalizedHighlights(step.Highlights)) > 0 {
		return dispositionAttention
	}
	if step.Noop == 0 {
		return dispositionAligned
	}
	return dispositionPlanned
}

func dispositionColor(disposition stepDisposition) string {
	switch disposition {
	case dispositionAligned:
		return logger.ColorGreen
	case dispositionAttention:
		return logger.ColorRed
	default:
		return logger.ColorBlue
	}
}

func dispositionText(disposition stepDisposition) string {
	switch disposition {
	case dispositionAligned:
		return "already aligned"
	case dispositionAttention:
		return "needs attention"
	default:
		return "change planned"
	}
}

func upperFirst(text string) string {
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func countPlanSteps(p *profile.Profile) int {
	if p == nil {
		return 0
	}

	total := 0
	for _, af := range p.ActionFiles {
		total += len(af.Steps)
	}
	return total
}

func overallSeverity(steps []StepPlan) string {
	max := "low"
	for _, s := range steps {
		switch strings.ToLower(s.Severity) {
		case "critical":
			return "critical"
		case "high":
			if max != "critical" {
				max = "high"
			}
		case "medium":
			if max == "low" {
				max = "medium"
			}
		}
	}
	return max
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return logger.ColorBrightRed + "CRITICAL" + logger.ColorReset
	case "high":
		return logger.ColorRed + "HIGH" + logger.ColorReset
	case "medium":
		return logger.ColorYellow + "MEDIUM" + logger.ColorReset
	case "low":
		return logger.ColorGreen + "LOW" + logger.ColorReset
	default:

		return sev
	}
}
