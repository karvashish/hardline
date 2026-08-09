package plan

import (
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestIsDiffHeaderLine(t *testing.T) {
	cases := map[string]bool{
		"--- current /etc/foo": true,
		"+++ desired /etc/foo": true,
		"@@ -1,2 +1,3 @@":      true,
		"   --- with leading":  true,
		"":                     false,
		"--no space":           false,
		"+plain content":       false,
		"-removed line":        false,
	}
	for line, want := range cases {
		if got := isDiffHeaderLine(line); got != want {
			t.Errorf("isDiffHeaderLine(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestNormalizeReportFormat(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"  ":       "",
		"json":     "json",
		"JSON":     "json",
		"yaml":     "yaml",
		"yml":      "yaml",
		"md":       "md",
		"markdown": "md",
		"xml":      "",
		"  Md  ":   "md",
	}
	for in, want := range cases {
		if got := normalizeReportFormat(in); got != want {
			t.Errorf("normalizeReportFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDispositionCodeAndStatusTitle(t *testing.T) {
	if got := dispositionCode(dispositionAligned); got != "already_aligned" {
		t.Errorf("aligned: got %q", got)
	}
	if got := dispositionCode(dispositionAttention); got != "needs_attention" {
		t.Errorf("attention: got %q", got)
	}
	if got := dispositionCode(dispositionPlanned); got != "change_planned" {
		t.Errorf("planned: got %q", got)
	}
	if got := dispositionCode(stepDisposition("unknown")); got != "change_planned" {
		t.Errorf("unknown disposition default: got %q", got)
	}

	if got := statusTitle("already_aligned"); got != "Already aligned" {
		t.Errorf("aligned title: got %q", got)
	}
	if got := statusTitle("needs_attention"); got != "Needs attention" {
		t.Errorf("attention title: got %q", got)
	}
	if got := statusTitle("change_planned"); got != "Change planned" {
		t.Errorf("planned title: got %q", got)
	}
	if got := statusTitle("unknown"); got != "Change planned" {
		t.Errorf("unknown title default: got %q", got)
	}
}

func TestNormalizedHighlights(t *testing.T) {
	if got := normalizedHighlights(nil); len(got) != 0 {
		t.Errorf("nil highlights: got %v", got)
	}
	in := []string{"a", "b", "c", "d"}
	got := normalizedHighlights(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 highlights, got %d (%v)", len(got), got)
	}
	if got[0] != "a" || got[1] != "b" {
		t.Errorf("expected [a b], got %v", got)
	}
}

func TestPreviewPlanLines(t *testing.T) {
	lines := []string{
		`package "a": installed -> upgraded`,
		"--- current /etc/foo",
		"+++ desired /etc/foo",
		"@@ -1,2 +1,3 @@",
		"+line one",
		"+line two",
		"+line three",
		`chain policy: accept -> drop`,
	}
	got := previewPlanLines(lines)
	for _, l := range got {
		if isDiffHeaderLine(l) {
			t.Errorf("header line %q leaked into preview", l)
		}
	}
	if len(got) != 5 {
		t.Errorf("expected 5 non-framing lines (nothing capped), got %d (%v)", len(got), got)
	}
}

func TestCollectPlannedChanges(t *testing.T) {
	planned := func(id, summary string) StepPlan {
		return StepPlan{
			PlanResult: pluginapi.PlanResult{WillChange: true, OperatorSummary: summary},
			StepID:     id,
			StepType:   "packages_apt",
		}
	}
	aligned := StepPlan{
		PlanResult: pluginapi.PlanResult{WillChange: false},
		StepID:     "ignore-me",
	}
	attention := StepPlan{
		PlanResult: pluginapi.PlanResult{WillChange: true, Highlights: []string{"oops"}},
		StepID:     "skip-me",
	}

	steps := []StepPlan{
		planned("install-curl", "install curl"),
		planned("install-curl", "install curl"),
		planned("install-jq", "install jq"),
		aligned,
		attention,
	}
	got := collectPlannedChanges(steps)
	if len(got) != 2 {
		t.Fatalf("expected 2 deduped planned changes, got %d (%v)", len(got), got)
	}
	if got[0] != "install-curl: install curl" || got[1] != "install-jq: install jq" {
		t.Errorf("unexpected planned changes: %v", got)
	}
}
