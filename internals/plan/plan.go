package plan

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var (
	planVersionCmd    = cli.VersionCmd
	planCompareSemVer = cli.CompareSemVer
	newPlanSSHClient  = connection.NewSSHClient
	runPlanForProfile = planProfile
	runPlanStep       = planStepWithRegistry
	ensurePlanPlugins = pluginapi.ValidateProfileSteps
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type planRunOptions struct {
	Host          string
	ProfileArg    string
	OverridesFile string
	ReportFile    string
	ReportFormat  string
}

type stepDisposition string

const (
	dispositionAligned   stepDisposition = "aligned"
	dispositionPlanned   stepDisposition = "planned"
	dispositionAttention stepDisposition = "attention"
)

func Plan(c cli.Command, b *verify.VerifiedBundle) error {
	if !c.Debug {
		target := displayTargetHost(c.Host)
		logger.Infof("Planning %s on %s\n", c.Profile, target)
	}

	logger.Debugf("plan: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	if err := validatePlanOutputs(c); err != nil {
		return logger.Wrap(err, "plan output configuration failed")
	}

	if b == nil || b.Profile == nil {
		return errors.New("plan requires a verified profile bundle")
	}
	p := b.Profile

	logger.Debugf("using verified profile bundle, starting validation\n")

	ver, schemaVer, err := planVersionCmd()
	if err != nil {
		return logger.Wrap(err, "hardline version check failed")
	}

	cmp, err := planCompareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		return logger.Wrap(err, "invalid profile.min_hardline value "+strconv.Quote(p.MinHardline))
	}

	if cmp < 0 {
		return errors.New("hardline version " + ver.String() + " is too old; minimum required is " + p.MinHardline)
	}

	if p.ProfileSchema > schemaVer {
		return errors.New("profile schema " + strconv.Itoa(p.ProfileSchema) + " is newer than supported " + strconv.Itoa(schemaVer) + "; please upgrade hardline")
	}

	if err := ensurePlanPlugins(registry.Shared(), p, b.Overrides); err != nil {
		return logger.Wrap(err, "step validation failed")
	}

	p.SetRuntimeOverrides(b.Overrides)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
		Port:    c.Port,
	}

	sshClient, err := newPlanSSHClient(*config)
	if err != nil {
		return logger.Wrap(err, "connect failed")
	}
	if sshClient != nil {
		defer sshClient.Close()
	}

	logger.Debugf("ssh connection established\n")

	if err := connection.CheckRemoteOS(sshClient, p.OS.Family, p.OS.Version, p.OS.Variant); err != nil {
		return logger.Wrap(err, "OS compatibility check failed")
	}

	if err := runPlanForProfile(sshClient, p, planRunOptions{
		Host:          c.Host,
		ProfileArg:    c.Profile,
		OverridesFile: c.OverridesFile,
		ReportFile:    c.ReportFile,
		ReportFormat:  c.ReportFormat,
	}); err != nil {
		return err
	}

	logger.Debugf("plan completed\n")
	return nil
}

func planProfile(client *remote.Client, p *profile.Profile, options planRunOptions) error {
	logger.Debugf("planProfile: %d action files\n", len(p.ActionFiles))

	var plans []StepPlan
	totalSteps := countPlanSteps(p)
	currentStep := 0
	stepChanges := make(map[string]bool)

	if !logger.DebugMode() {
		var header strings.Builder
		writePlanHeader(&header, *p, options.Host)
		logger.Infof("%s", header.String())
	}

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			currentStep++
			logger.Infof("Inspecting %02d/%02d %s [%s] ", currentStep, totalSteps, step.ID, step.PluginName())
			stop := utils.Throbber()
			logger.Debugf("planStep: id=%q type=%q\n", step.ID, step.PluginName())

			sp, err := runPlanStep(registry.Shared(), client, p, step, stepChanges)
			if stop != nil {
				stop()
			}

			if err != nil {
				logger.Infof("\n")
				return err
			}

			// Record the predicted outcome for downstream steps (service restart on_change)
			stepChanges[step.ID] = sp.WillChange

			plans = append(plans, sp)

			logger.Infof("\n%s", renderCompactStepResult(sp))
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
	if logger.DebugMode() {
		logger.Infof("%s", renderDetailedPlan(profile, steps, hostname))
	} else {
		logger.Infof("%s", renderCompactPlan(profile, steps, hostname))
	}
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
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func renderCompactPlan(profile profile.Profile, steps []StepPlan, hostname string) string {
	var b strings.Builder

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

// PrintPlanNextSteps prints the "NEXT STEPS" block after a standalone plan run.
// It is not called when plan runs as part of apply.
func PrintPlanNextSteps(c cli.Command) {
	var b strings.Builder
	fmt.Fprintf(&b, "%sNEXT STEPS%s\n", logger.ColorCyan+logger.ColorBold, logger.ColorReset)
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 60))
	cmd := applyCommand(c.Profile, c.Host, c.OverridesFile)
	fmt.Fprintf(&b, "Apply changes:\n  %s\n\n", logger.ColorBold+cmd+logger.ColorReset)
	fmt.Fprintf(&b, "%sPlan complete. No changes have been made.%s\n", logger.ColorGreen, logger.ColorReset)
	logger.Infof("%s", b.String())
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
	fmt.Fprintf(b, "%sRollback%s        : %sAVAILABLE%s\n\n",
		logger.ColorBold, logger.ColorReset, logger.ColorGreen, logger.ColorReset)
	fmt.Fprintf(b, "%sNo changes will be made until 'hardline apply' is executed.%s\n\n",
		logger.ColorDim, logger.ColorReset)
}

func renderCompactStepResult(step StepPlan) string {
	var b strings.Builder

	disposition := stepDispositionFor(step)
	fmt.Fprintf(&b, "  %s%-15s%s %s\n",
		dispositionColor(disposition), strings.ToUpper(dispositionText(disposition)), logger.ColorReset,
		compactOperatorSummary(step))

	for _, line := range previewPlanLines(step.Diff) {
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

// previewPlanLines renders the diff lines for the compact plan log. It drops
// only the unified-diff framing lines ("--- / +++ / @@") and shows every
// remaining change line; nothing is capped, so the log reflects the full set
// of changes for the step.
func previewPlanLines(lines []string) []string {
	clean := normalizedReportLines(lines)
	out := clean[:0]
	for _, line := range clean {
		if isDiffHeaderLine(line) {
			continue
		}
		out = append(out, line)
	}
	return out
}

// isDiffHeaderLine reports whether a line is a unified-diff framing line
// ("--- current ...", "+++ desired ...", "@@ ...") that is meaningless without
// the content lines beneath it. Plan previews strip these so every line shown
// to the operator is substantive.
func isDiffHeaderLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(trimmed, "--- "):
		return true
	case strings.HasPrefix(trimmed, "+++ "):
		return true
	case strings.HasPrefix(trimmed, "@@"):
		return true
	}
	return false
}

func normalizeLogText(text string) string {
	clean := ansiPattern.ReplaceAllString(text, "")
	return strings.Join(strings.Fields(clean), " ")
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
	if !step.WillChange {
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
