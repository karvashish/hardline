package profile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Ledger statuses. A control is either implemented by this profile or
// explicitly not, and "not" has to say which kind of not: something the profile
// only checks, something the site must decide, something that belongs to
// provisioning, something deferred, or something that does not apply to this
// target. Silence is what a coverage claim must never be.
const (
	StatusImplemented           = "implemented"
	StatusAssertedPrerequisite  = "asserted_prerequisite"
	StatusSiteRequired          = "site_required"
	StatusProvisioning          = "provisioning"
	StatusDeferred              = "deferred"
	StatusNotApplicable         = "not_applicable"
	ledgerRetrievedAtDateFormat = "2006-01-02"
)

var ledgerControlIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// LedgerControl is one control this profile makes a claim about: what state it
// wants, where that state came from, which steps produce it, and how the claim
// was tested. It is ordinary signed profile content, so a claim cannot be
// edited after signing any more than an action file can.
type LedgerControl struct {
	HardlineID   string `json:"hardline_id"`
	DesiredState string `json:"desired_state"`
	// SourceTitle and SourceURL identify an engineering reference, not an
	// endorsement. CopiedCode records, per control, that no benchmark text or
	// script was copied into this profile; it must be false.
	SourceTitle           string   `json:"source_title"`
	SourceURL             string   `json:"source_url"`
	SourceVersionOrCommit string   `json:"source_version_or_commit"`
	RetrievedAt           string   `json:"retrieved_at"`
	ImplementationActions []string `json:"implementation_actions"`
	Status                string   `json:"status"`
	Tests                 []string `json:"tests"`
	CopiedCode            bool     `json:"copied_code"`
}

// CoverageLedger is the whole set of claims a profile makes.
type CoverageLedger struct {
	Controls []LedgerControl `json:"controls"`
}

// LoadCoverageLedger decodes the ledger a profile declares. Like every other
// reference, it is read from the signed snapshot rather than from disk.
func (p *Profile) LoadCoverageLedger() (*CoverageLedger, error) {
	rel := strings.TrimSpace(p.CoverageLedger)
	if rel == "" {
		return nil, nil
	}

	content, err := p.signedBytes(rel)
	if err != nil {
		return nil, fmt.Errorf("profile coverage_ledger %w", err)
	}
	var ledger CoverageLedger
	if err := json.Unmarshal(content, &ledger); err != nil {
		return nil, fmt.Errorf("decode coverage ledger %q: %w", rel, err)
	}
	return &ledger, nil
}

// validateCoverageLedger checks the claims against the profile that makes them.
// A ledger that names a step which does not exist, or leaves a step unclaimed,
// describes a profile other than this one.
func (p *Profile) validateCoverageLedger() error {
	ledger, err := p.LoadCoverageLedger()
	if err != nil {
		return err
	}
	if ledger == nil {
		return nil
	}
	if len(ledger.Controls) == 0 {
		return fmt.Errorf("coverage ledger %q declares no controls", p.CoverageLedger)
	}

	steps := map[string]struct{}{}
	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			steps[strings.TrimSpace(step.ID)] = struct{}{}
		}
	}

	seenControls := map[string]struct{}{}
	claimedSteps := map[string]string{}
	for i, control := range ledger.Controls {
		if err := validateLedgerControl(control, i, steps, seenControls, claimedSteps); err != nil {
			return err
		}
	}

	var unclaimed []string
	for id := range steps {
		if _, ok := claimedSteps[id]; !ok {
			unclaimed = append(unclaimed, id)
		}
	}
	if len(unclaimed) > 0 {
		sort.Strings(unclaimed)
		return fmt.Errorf("coverage ledger does not account for step(s): %s", strings.Join(unclaimed, ", "))
	}
	return nil
}

func validateLedgerControl(control LedgerControl, index int, steps, seenControls map[string]struct{}, claimedSteps map[string]string) error {
	id := strings.TrimSpace(control.HardlineID)
	if id == "" {
		return fmt.Errorf("coverage ledger control %d has an empty hardline_id", index)
	}
	if !ledgerControlIDPattern.MatchString(id) {
		return fmt.Errorf("coverage ledger control %q has an invalid hardline_id", id)
	}
	if _, dup := seenControls[id]; dup {
		return fmt.Errorf("coverage ledger declares control %q twice", id)
	}
	seenControls[id] = struct{}{}

	if strings.TrimSpace(control.DesiredState) == "" {
		return fmt.Errorf("coverage ledger control %q does not say what state it wants", id)
	}
	if control.CopiedCode {
		return fmt.Errorf("coverage ledger control %q sets copied_code, which this profile does not permit", id)
	}

	switch control.Status {
	case StatusImplemented, StatusAssertedPrerequisite, StatusSiteRequired,
		StatusProvisioning, StatusDeferred, StatusNotApplicable:
	default:
		return fmt.Errorf("coverage ledger control %q has unsupported status %q", id, control.Status)
	}

	for _, field := range []struct{ name, value string }{
		{"source_title", control.SourceTitle},
		{"source_url", control.SourceURL},
		{"source_version_or_commit", control.SourceVersionOrCommit},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("coverage ledger control %q has an empty %s", id, field.name)
		}
	}
	if _, err := time.Parse(ledgerRetrievedAtDateFormat, strings.TrimSpace(control.RetrievedAt)); err != nil {
		return fmt.Errorf("coverage ledger control %q has retrieved_at %q, which is not a %s date",
			id, control.RetrievedAt, ledgerRetrievedAtDateFormat)
	}

	// Only an implemented control runs steps. Anything else claims the profile
	// does not act, so naming a step there would contradict the status itself.
	if control.Status != StatusImplemented {
		if len(control.ImplementationActions) > 0 {
			return fmt.Errorf("coverage ledger control %q is %q but names implementation_actions", id, control.Status)
		}
		return nil
	}
	if len(control.ImplementationActions) == 0 {
		return fmt.Errorf("coverage ledger control %q is implemented but names no step", id)
	}
	for _, stepID := range control.ImplementationActions {
		trimmed := strings.TrimSpace(stepID)
		if _, ok := steps[trimmed]; !ok {
			return fmt.Errorf("coverage ledger control %q names step %q, which this profile does not declare", id, stepID)
		}
		if owner, dup := claimedSteps[trimmed]; dup {
			return fmt.Errorf("step %q is claimed by both control %q and control %q", trimmed, owner, id)
		}
		claimedSteps[trimmed] = id
	}
	return nil
}
