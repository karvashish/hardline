package template

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

type templateStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type templateCompareRuntime interface {
	templateStatRuntime
	ReadRootFile(path string) (string, error)
}

func Apply(ctx pluginapi.Context, t *Spec) error {
	logger.Debugf("handleTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	if ctx.Profile == nil {
		return fmt.Errorf("template step: profile context is required")
	}
	if ctx.Host == nil {
		return fmt.Errorf("template step: host context is required")
	}
	dest := strings.TrimSpace(t.Dest)
	if err := pluginapi.EnforceManagedPath(dest); err != nil {
		return fmt.Errorf("template apply: %w", err)
	}

	data, err := ctx.Profile.LoadTemplate(t.Src)
	if err != nil {
		return fmt.Errorf("load template %q: %w", t.Src, err)
	}

	mode := os.FileMode(0600)
	if t.Mode != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err != nil {
			return fmt.Errorf("template %q: invalid mode %q (expected octal, e.g. 644): %w", t.Src, t.Mode, err)
		}
		mode = os.FileMode(parsed)
	}

	matches, err := templateDestinationMatches(ctx.Host, dest, data, mode)
	if err != nil {
		return fmt.Errorf("compare destination %s: %w", dest, err)
	}
	if matches {
		logger.Debugf("handleTemplate: destination %q already matches, skipping write\n", dest)
		return nil
	}

	dir := path.Dir(dest)
	if dir != "" && dir != "." {
		if err := ctx.Host.RunRoot("mkdir -p " + pluginapi.ShellArg(dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	if err := ctx.Host.WriteRootFile(dest, data, mode); err != nil {
		return fmt.Errorf("write root file %s: %w", dest, err)
	}

	return nil
}

func templateDestinationMatches(rt templateCompareRuntime, dest string, rendered []byte, mode os.FileMode) (bool, error) {
	size, currentMode, err := statTemplateDestination(rt, dest)
	if err != nil {
		return false, err
	}
	if size < 0 || currentMode.Perm() != mode.Perm() {
		return false, nil
	}

	current, err := rt.ReadRootFile(dest)
	if err != nil {
		return false, err
	}
	return current == string(rendered), nil
}

func Plan(ctx pluginapi.Context, t *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	if ctx.Profile == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("template step: profile context is required")
	}
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("template step: host context is required")
	}
	dest := strings.TrimSpace(t.Dest)
	if err := pluginapi.EnforceManagedPath(dest); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("template plan: %w", err)
	}

	rendered, err := ctx.Profile.LoadTemplate(t.Src)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("load template %q: %w", t.Src, err)
	}

	var details []string
	var diff []string
	var highlights []string

	mode := os.FileMode(0600)
	modeText := strings.TrimSpace(t.Mode)
	if modeText == "" {
		modeText = "0600 (default in executor)"
	} else {
		var parsed uint64
		if _, err := fmt.Sscanf(modeText, "%o", &parsed); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	exists := false
	modeMatches := false
	contentMatches := false
	compareReady := false
	currentContent := ""

	size, currentMode, err := statTemplateDestination(ctx.Host, dest)
	if err != nil {
		highlights = append(highlights, fmt.Sprintf("cannot inspect destination %q (%v)", dest, err))
		details = append(details,
			logger.ColorRed+fmt.Sprintf("cannot stat destination %q (%v)", dest, err)+logger.ColorReset,
		)
	} else if size < 0 {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sdoes not exist (file will be created)%s",
			logger.ColorBlue, dest, logger.ColorReset,
			logger.ColorGreen, logger.ColorReset,
		)
		details = append(details, line)
		diff = append(diff, fmt.Sprintf("file %q: absent -> present (mode %#o)", dest, mode.Perm()))
		diff = append(diff, renderTemplateContentDiff(dest, "", string(rendered), false)...)
	} else {
		exists = true
		line := fmt.Sprintf(
			"%sdestination %q:%s %sexists (size=%d bytes, mode=%#o)%s",
			logger.ColorBlue, dest, logger.ColorReset,
			logger.ColorYellow, size, currentMode.Perm(), logger.ColorReset,
		)
		details = append(details, line)
		modeMatches = currentMode.Perm() == mode.Perm()
		if modeMatches {
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("destination mode matches desired mode %#o", mode.Perm())+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorYellow+fmt.Sprintf("destination mode differs (current=%#o desired=%#o)", currentMode.Perm(), mode.Perm())+logger.ColorReset,
			)
		}

		current, readErr := ctx.Host.ReadRootFile(dest)
		if readErr != nil {
			highlights = append(highlights, fmt.Sprintf("cannot compare rendered content for %q (%v)", dest, readErr))
			details = append(details,
				logger.ColorRed+fmt.Sprintf("cannot compare content for %q (%v)", dest, readErr)+logger.ColorReset,
			)
		} else {
			compareReady = true
			currentContent = current
			contentMatches = current == string(rendered)
			if contentMatches {
				details = append(details,
					logger.ColorGreen+"destination content matches rendered template"+logger.ColorReset,
				)
			} else {
				details = append(details,
					logger.ColorYellow+"destination content differs from rendered template (rewrite needed)"+logger.ColorReset,
				)
			}
		}

		if !modeMatches {
			diff = append(diff,
				fmt.Sprintf("file mode %q: %#o -> %#o", dest, currentMode.Perm(), mode.Perm()),
			)
		}
		if compareReady && !contentMatches {
			diff = append(diff, renderTemplateContentDiff(dest, currentContent, string(rendered), true)...)
		}
	}

	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: template %q rendered to %q with mode %s", t.Src, dest, modeText)+logger.ColorReset,
	)

	summary := fmt.Sprintf("template step: render %q to %q (mode %s)", t.Src, dest, modeText)
	operatorSummary := fmt.Sprintf("Write rendered configuration from %q to %q with mode %s", t.Src, dest, modeText)
	willChange := true
	if exists && compareReady && modeMatches && contentMatches {
		summary = fmt.Sprintf("template step: no rewrite required for %q (content and mode already match)", dest)
		operatorSummary = fmt.Sprintf("%q already matches the desired content and mode", dest)
		willChange = false
	}
	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Diff:            diff,
		WillChange:      willChange,
		OperatorSummary: operatorSummary,
		Highlights:      highlights,
	}, nil
}

const templateDiffPreviewLimit = 40

type templateDiffEdit struct {
	kind byte
	line string
}

func renderTemplateContentDiff(dest string, current string, desired string, existed bool) []string {
	edits := diffTemplateLines(current, desired)
	changed := 0
	for _, edit := range edits {
		if edit.kind != ' ' {
			changed++
		}
	}
	if changed == 0 {
		return nil
	}

	lines := []string{
		fmt.Sprintf(`--- current %s%s`, dest, templateCurrentSuffix(existed)),
		fmt.Sprintf(`+++ desired %s`, dest),
	}
	emitted := 0
	for _, edit := range edits {
		if edit.kind == ' ' {
			continue
		}
		lines = append(lines, fmt.Sprintf("%c%s", edit.kind, edit.line))
		emitted++
		if emitted >= templateDiffPreviewLimit {
			break
		}
	}
	if emitted < changed {
		lines = append(lines, fmt.Sprintf("... %d more content diff line(s) omitted", changed-emitted))
	}
	return lines
}

func templateCurrentSuffix(existed bool) string {
	if existed {
		return ""
	}
	return " (absent)"
}

func diffTemplateLines(current string, desired string) []templateDiffEdit {
	currentLines := splitTemplateDiffLines(current)
	desiredLines := splitTemplateDiffLines(desired)

	dp := make([][]int, len(currentLines)+1)
	for i := range dp {
		dp[i] = make([]int, len(desiredLines)+1)
	}

	for i := len(currentLines) - 1; i >= 0; i-- {
		for j := len(desiredLines) - 1; j >= 0; j-- {
			if currentLines[i] == desiredLines[j] {
				dp[i][j] = dp[i+1][j+1] + 1
				continue
			}
			if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
				continue
			}
			dp[i][j] = dp[i][j+1]
		}
	}

	var edits []templateDiffEdit
	i := 0
	j := 0
	for i < len(currentLines) && j < len(desiredLines) {
		if currentLines[i] == desiredLines[j] {
			edits = append(edits, templateDiffEdit{kind: ' ', line: currentLines[i]})
			i++
			j++
			continue
		}
		if dp[i+1][j] >= dp[i][j+1] {
			edits = append(edits, templateDiffEdit{kind: '-', line: currentLines[i]})
			i++
			continue
		}
		edits = append(edits, templateDiffEdit{kind: '+', line: desiredLines[j]})
		j++
	}
	for i < len(currentLines) {
		edits = append(edits, templateDiffEdit{kind: '-', line: currentLines[i]})
		i++
	}
	for j < len(desiredLines) {
		edits = append(edits, templateDiffEdit{kind: '+', line: desiredLines[j]})
		j++
	}
	return edits
}

func splitTemplateDiffLines(text string) []string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	if normalized == "" {
		return nil
	}
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func statTemplateDestination(rt templateStatRuntime, dest string) (int64, os.FileMode, error) {
	if rt == nil {
		return 0, 0, fmt.Errorf("runtime is required")
	}
	if err := rt.RunRoot(fmt.Sprintf("test -e %s", pluginapi.ShellArg(dest))); err != nil {
		return -1, 0, nil
	}

	out, err := rt.RunRootWithOutput(fmt.Sprintf("stat -c '%%a %%s' -- %s", pluginapi.ShellArg(dest)))
	if err != nil {
		return 0, 0, err
	}

	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) != 2 {
		return 0, 0, fmt.Errorf("parse stat output for %q: unexpected format %q", dest, strings.TrimSpace(out))
	}

	perm, err := strconv.ParseUint(fields[0], 8, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stat mode for %q: %w", dest, err)
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse stat size for %q: %w", dest, err)
	}

	return size, os.FileMode(perm), nil
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=template): template spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("template step: host context is required")
	}

	dest := strings.TrimSpace(spec.Dest)
	if err := pluginapi.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=template): %w", stepID, err)
	}

	snap, err := pluginapi.SnapshotRemoteFile(ctx.Host, dest)
	if err != nil {
		return record, fmt.Errorf("capture template snapshot for %q: %w", dest, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectFile, File: &snap},
	}
	return record, nil
}
