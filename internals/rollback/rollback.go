package rollback

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/internals/verify"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

var rollbackNow = time.Now

var (
	newSSHClient       = connection.NewSSHClient
	ensureRollbackSudo = connection.EnsureNonInteractiveSudo
	runRollbackCommand = rollbackCommand
	loadRemoteJournal  = func(client *remote.Client, profileID string) (*Journal, error) {
		return LoadRemoteLast(client, profileID)
	}
	deleteJournal = func(client *remote.Client, profileID, runID string) error {
		return DeleteRemoteJournal(client, profileID, runID)
	}
	loadLocalJournal    = LoadLast
	saveLocalJournal    = (*Journal).SaveLast
	removeLocalJournal  = (*Journal).RemoveLast
	saveRemoteJournal   = SaveRemoteLast
	acquireMutationLock = remote.AcquireMutationLock
	releaseMutationLock = remote.ReleaseMutationLock
	lookupPlugin        = registry.Shared().Lookup
	exitProcess         = os.Exit
)

func Rollback(c cli.Command, b *verify.VerifiedBundle) {
	if err := runRollbackCommand(c, b); err != nil {
		logger.Errorf("rollback failed: %v\n", err)
		exitProcess(1)
	}
}

func rollbackCommand(c cli.Command, b *verify.VerifiedBundle) error {
	logger.Infof("rollback %s\n", c.Profile)
	runStart := rollbackNow()

	if b == nil || b.Profile == nil {
		return fmt.Errorf("rollback requires a verified profile bundle")
	}
	profileID := b.Profile.ID

	cfg := connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
		Port:    c.Port,
	}
	client, err := newSSHClient(cfg)
	if err != nil {
		return fmt.Errorf("connect failed: %w", err)
	}
	if client != nil {
		defer client.Close()
	}

	if err := ensureRollbackSudo(client); err != nil {
		return fmt.Errorf("sudo preflight failed: %w", err)
	}

	// The same host lock apply takes. Without it a rollback can revert steps an
	// apply is concurrently writing, and neither run ends up authoritative.
	if err := acquireMutationLock(client); err != nil {
		return err
	}
	defer func() {
		if releaseErr := releaseMutationLock(client); releaseErr != nil {
			logger.Warnf("release mutation lock failed: %v\n", releaseErr)
		}
	}()

	journal, err := loadRollbackJournal(client, c, profileID)
	if err != nil {
		return err
	}
	if journal.Status != "success" {
		return fmt.Errorf("last run is not marked successful (status=%q)", journal.Status)
	}

	if data, err := marshalJournal(journal); err == nil {
		logger.Infof("journal %s (run %s applied %s):\n%s\n", profileID, journal.RunID, journal.CreatedAt, string(data))
	}

	// Claim the journal before the first revert. If this run dies partway
	// through, the journal is left saying "rolling_back", and the next rollback
	// refuses it on the status check rather than replaying a set of before
	// states that have already been half-applied.
	if err := claimJournal(client, c, journal); err != nil {
		return err
	}

	degraded, err := executeRollbackSteps(client, journal.Steps, true, false, c.ForceRollback)
	if err != nil {
		return err
	}

	// Consuming the journal is part of the rollback, not an afterthought: a
	// journal that survives a completed rollback can be replayed against a host
	// whose state it no longer describes.
	if err := consumeJournal(client, c, journal); err != nil {
		return err
	}

	writeRollbackFooter(journal, degraded, rollbackNow().Sub(runStart))
	if len(degraded) > 0 {
		return fmt.Errorf("rollback completed with degraded restoration:\n  %s", strings.Join(degraded, "\n  "))
	}
	return nil
}

// loadRollbackJournal picks the journal this rollback is undoing. The
// runner-side copy is only consulted when asked for, because it exists exactly
// when apply could not commit the target journal.
func loadRollbackJournal(client *remote.Client, c cli.Command, profileID string) (*Journal, error) {
	if c.LocalJournal {
		journal, err := loadLocalJournal(c.Host, profileID)
		if err != nil {
			return nil, fmt.Errorf("read runner-side journal for profile %q on host %q: %w", profileID, c.Host, err)
		}
		// The journal records the host it was written for, so a local file
		// cannot be pointed at a different machine by changing --host alone.
		if journal.Host != strings.TrimSpace(c.Host) {
			return nil, fmt.Errorf("runner-side journal was written for host %q, not %q", journal.Host, c.Host)
		}
		logger.Warnf("using the runner-side journal for %s; the target journal was never committed\n", profileID)
		return journal, nil
	}
	return loadRemoteJournal(client, profileID)
}

// claimJournal marks the journal as being consumed, before anything is
// reverted. Status is the same field the load path checks, so a journal left
// behind by an interrupted rollback is refused by the existing status gate.
func claimJournal(client *remote.Client, c cli.Command, journal *Journal) error {
	restore := journal.Status
	journal.Status = "rolling_back"

	var err error
	if c.LocalJournal {
		err = saveLocalJournal(journal)
	} else {
		err = saveRemoteJournal(client, journal)
	}
	if err != nil {
		journal.Status = restore
		return fmt.Errorf("claim journal %q before rollback: %w", journal.RunID, err)
	}
	return nil
}

func consumeJournal(client *remote.Client, c cli.Command, journal *Journal) error {
	if c.LocalJournal {
		if err := removeLocalJournal(journal); err != nil {
			return fmt.Errorf("delete runner-side journal %q after rollback: %w", journal.RunID, err)
		}
		return nil
	}
	if err := deleteJournal(client, journal.ProfileID, journal.RunID); err != nil {
		return fmt.Errorf("delete remote journal %q after rollback: %w", journal.RunID, err)
	}
	return nil
}

func writeRollbackFooter(journal *Journal, degraded []string, duration time.Duration) {
	var b strings.Builder
	row := func(label, value string) {
		b.WriteString(label)
		b.WriteString(value)
		b.WriteString("\n")
	}

	heading := "ROLLBACK COMPLETE"
	if len(degraded) > 0 {
		heading = "ROLLBACK INCOMPLETE"
	}
	b.WriteString("\n" + logger.ColorCyan + logger.ColorBold)
	b.WriteString(heading)
	b.WriteString(logger.ColorReset)
	b.WriteString("\n")
	row("", strings.Repeat("-", 60))
	if journal != nil {
		row(logger.ColorBold+"Profile"+logger.ColorReset+"  : ", journal.ProfileID)
		if journal.RunID != "" {
			row(logger.ColorBold+"Run ID"+logger.ColorReset+"   : ", journal.RunID)
		}
		row(logger.ColorBold+"Steps"+logger.ColorReset+"    : ", strconv.Itoa(len(journal.Steps)))
	}
	row(logger.ColorBold+"Duration"+logger.ColorReset+" : ", formatRollbackDuration(duration))
	if len(degraded) > 0 {
		row(logger.ColorBold+"Restored"+logger.ColorReset+" : ",
			logger.ColorYellow+"PARTIAL ("+strconv.Itoa(len(degraded))+" object(s) not restored)"+logger.ColorReset)
		for _, note := range degraded {
			row("  - ", note)
		}
	}
	b.WriteString("\n")
	logger.Infof("%s", b.String())
}

func stepActuallyChanged(step StepRecord) bool {
	if len(step.Before) == 0 && len(step.After) == 0 {
		return false
	}
	beforeJSON, err1 := json.Marshal(step.Before)
	afterJSON, err2 := json.Marshal(step.After)
	if err1 != nil || err2 != nil {
		return true
	}
	return string(beforeJSON) != string(afterJSON)
}

// serviceReloadTriggered re-runs a reload/restart on rollback when its config dep
// is reverted: on_change fires on a dep delta, always/absent unconditionally.
func serviceReloadTriggered(step StepRecord, all []StepRecord) bool {
	r := step.Reload
	if r == nil || !isServiceReloadAction(r.Action) {
		return false
	}
	if r.RestartPolicy == "on_change" {
		for _, dep := range r.RestartDeps {
			if stepChangedByID(all, dep) {
				return true
			}
		}
		return false
	}
	return true
}

func isServiceReloadAction(action string) bool {
	switch action {
	case "restarted", "restart", "reloaded", "reload", "reload-or-restart":
		return true
	default:
		return false
	}
}

func stepChangedByID(steps []StepRecord, id string) bool {
	for i := range steps {
		if steps[i].ID == id {
			return stepActuallyChanged(steps[i])
		}
	}
	return false
}

// RollbackSteps is the automatic revert apply runs when a step fails. It holds
// the mutation lock apply already took, so it does not take it again.
func RollbackSteps(client *remote.Client, steps []StepRecord) error {
	if err := ensureRollbackSudo(client); err != nil {
		return fmt.Errorf("sudo preflight failed: %w", err)
	}
	degraded, err := executeRollbackSteps(client, steps, false, false, false)
	if err != nil {
		return err
	}
	if len(degraded) > 0 {
		return fmt.Errorf("automatic rollback completed with degraded restoration:\n  %s", strings.Join(degraded, "\n  "))
	}
	return nil
}

func executeRollbackSteps(client *remote.Client, steps []StepRecord, showProgress bool, strictBestEffort bool, forceRollback bool) ([]string, error) {
	// Every conflict is found before the first restore. Checking a step and
	// immediately reverting it means a conflict on an early step surfaces only
	// after later steps have already been undone, leaving the host in a state
	// that is neither the profile's nor the one it had before the run.
	if err := preflightRollbackConflicts(client, steps, forceRollback); err != nil {
		return nil, err
	}

	total := countRollbackSteps(steps)
	var deferredServiceSteps []StepRecord
	var degraded []string
	current := 0

	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if !rollbackStepApplies(step, steps) {
			current++
			if showProgress {
				logger.Infof("Reverting %02d/%02d %s [%s] %sSKIPPED%s (no delta)\n",
					current, total, step.ID, step.Type,
					logger.ColorDim, logger.ColorReset)
			}
			continue
		}
		if stepHasServiceObjects(step) {
			deferredServiceSteps = append(deferredServiceSteps, step)
			continue
		}
		current++
		stepDegraded, err := runRollbackOneStep(client, step, current, total, showProgress, strictBestEffort)
		degraded = append(degraded, stepDegraded...)
		if err != nil {
			return degraded, err
		}
	}

	for _, step := range deferredServiceSteps {
		current++
		stepDegraded, err := runRollbackOneStep(client, step, current, total, showProgress, strictBestEffort)
		degraded = append(degraded, stepDegraded...)
		if err != nil {
			return degraded, err
		}
	}
	return degraded, nil
}

// rollbackStepApplies reports whether a journalled step has anything to undo.
func rollbackStepApplies(step StepRecord, all []StepRecord) bool {
	return stepActuallyChanged(step) || serviceReloadTriggered(step, all)
}

// preflightRollbackConflicts collects the drift across every step that would be
// reverted and reports all of it at once, so the operator decides against the
// complete picture rather than one step at a time.
func preflightRollbackConflicts(client *remote.Client, steps []StepRecord, forceRollback bool) error {
	// Every plugin the rollback will need has to exist before anything is
	// reverted. Discovering a missing plugin partway through leaves the host
	// half-restored, which is the failure this preflight exists to prevent.
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if !rollbackStepApplies(step, steps) || step.RollbackMode == pluginapi.ModeNoop {
			continue
		}
		if _, ok := lookupPlugin(step.Type); !ok {
			return fmt.Errorf("rollback step %q: plugin %q is not registered; refusing to revert any step", step.ID, step.Type)
		}
	}

	var report strings.Builder
	conflicted := 0

	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if !rollbackStepApplies(step, steps) {
			continue
		}
		conflicts := checkStepConflicts(client, step)
		if len(conflicts) == 0 {
			continue
		}
		conflicted++
		fmt.Fprintf(&report, "step %q: files were modified after this profile ran — rolling back will overwrite those changes:\n", step.ID)
		for _, c := range conflicts {
			report.WriteString("  ")
			report.WriteString(c)
			report.WriteString("\n")
		}
	}

	if conflicted == 0 {
		return nil
	}
	if !forceRollback {
		return fmt.Errorf("%sre-run with --force-rollback to overwrite", report.String())
	}
	logger.Warnf("WARNING: %s--force-rollback set, proceeding anyway\n", report.String())
	return nil
}

func runRollbackOneStep(client *remote.Client, step StepRecord, current, total int, showProgress, strictBestEffort bool) ([]string, error) {
	if showProgress {
		logger.Infof("Reverting %02d/%02d %s [%s] ", current, total, step.ID, step.Type)
	}
	var stop func()
	start := rollbackNow()
	if showProgress {
		stop = utils.Throbber()
	}
	degraded, err := rollbackStepWithMode(client, step, strictBestEffort)
	if stop != nil {
		stop()
	}
	duration := rollbackNow().Sub(start)
	if err != nil {
		if showProgress {
			logger.Infof("%s✗ FAILED%s (%s)\n", logger.ColorRed+logger.ColorBold, logger.ColorReset, formatRollbackDuration(duration))
		}
		return degraded, fmt.Errorf("rollback step %q failed: %w", step.ID, err)
	}
	if showProgress {
		if len(degraded) > 0 {
			logger.Infof("%s✓ PARTIAL%s (%s)\n", logger.ColorYellow+logger.ColorBold, logger.ColorReset, formatRollbackDuration(duration))
		} else {
			logger.Infof("%s✓ REVERTED%s (%s)\n", logger.ColorGreen+logger.ColorBold, logger.ColorReset, formatRollbackDuration(duration))
		}
	}
	return degraded, nil
}

func countRollbackSteps(steps []StepRecord) int {
	return len(steps)
}

// formatRollbackDuration matches the apply-step duration format.
func formatRollbackDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Second {
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	}
	if d < time.Minute {
		seconds := float64(d) / float64(time.Second)
		return strconv.FormatFloat(seconds, 'f', 1, 64) + "s"
	}
	minutes := int(d / time.Minute)
	seconds := int((d % time.Minute) / time.Second)
	return strconv.Itoa(minutes) + "m" + strconv.Itoa(seconds) + "s"
}

// checkStepConflicts delegates to the step's owning plugin to compare the
// journal's after snapshot against live remote state. A non-empty result means
// the state changed after this profile ran.
func checkStepConflicts(client *remote.Client, step StepRecord) []string {
	plug, ok := lookupPlugin(step.Type)
	if !ok {
		return nil
	}
	var conflicts []string
	for _, afterObj := range step.After {
		conflicts = append(conflicts, plug.DetectConflict(client, afterObj)...)
	}
	return conflicts
}

func stepHasServiceObjects(step StepRecord) bool {
	for _, obj := range step.Before {
		if obj.Kind == pluginapi.ObjectService {
			return true
		}
	}
	return false
}

// rollbackStepWithMode reverts one step. Failures a best-effort step is allowed
// to absorb are returned as degraded notes rather than swallowed: a rollback
// that could not restore everything it recorded must not report as if it did.
func rollbackStepWithMode(client *remote.Client, step StepRecord, strictBestEffort bool) (degraded []string, err error) {
	if step.RollbackMode == pluginapi.ModeNoop {
		return nil, nil
	}

	plug, ok := lookupPlugin(step.Type)
	if !ok {
		return nil, fmt.Errorf("rollback step %q: plugin %q is not registered", step.ID, step.Type)
	}

	for i := len(step.Before) - 1; i >= 0; i-- {
		obj := step.Before[i]
		rbErr := plug.Rollback(client, obj)
		if rbErr == nil {
			continue
		}
		if step.RollbackMode == pluginapi.ModeBestEffort && !strictBestEffort {
			logger.Warnf("rollback warning (best-effort, step=%s): %v\n", step.ID, rbErr)
			degraded = append(degraded, fmt.Sprintf("step %q (%s): %v", step.ID, step.Type, rbErr))
			continue
		}
		return degraded, rbErr
	}

	return degraded, nil
}
