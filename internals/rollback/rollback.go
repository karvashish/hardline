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
	resuming := false
	switch journal.Status {
	case "success":
	case "rolling_back":
		resuming = true
		logger.Warnf("run %s was already being rolled back and did not finish; resuming it\n", journal.RunID)
	default:
		return fmt.Errorf("last run is not marked successful (status=%q)", journal.Status)
	}

	if data, err := marshalJournal(journal); err == nil {
		logger.Infof("journal %s (run %s applied %s):\n%s\n", profileID, journal.RunID, journal.CreatedAt, string(data))
	}

	if err := preflightRollbackConflicts(client, journal.Steps, c.ForceRollback, resuming); err != nil {
		return err
	}

	if err := claimJournal(client, c, journal); err != nil {
		return err
	}

	degraded, err := executeRollbackSteps(client, journal.Steps, true)
	if err != nil {
		return fmt.Errorf("%w; the host is partly reverted and run %s is still journalled, so running rollback again resumes it", err, journal.RunID)
	}

	if err := consumeJournal(client, c, journal); err != nil {
		return err
	}

	writeRollbackFooter(journal, degraded, rollbackNow().Sub(runStart))
	if len(degraded) > 0 {
		return fmt.Errorf("rollback completed with degraded restoration:\n  %s", strings.Join(degraded, "\n  "))
	}
	return nil
}

func loadRollbackJournal(client *remote.Client, c cli.Command, profileID string) (*Journal, error) {
	if c.LocalJournal {
		journal, err := loadLocalJournal(c.Host, profileID)
		if err != nil {
			return nil, fmt.Errorf("read runner-side journal for profile %q on host %q: %w", profileID, c.Host, err)
		}
		if journal.Host != strings.TrimSpace(c.Host) {
			return nil, fmt.Errorf("runner-side journal was written for host %q, not %q", journal.Host, c.Host)
		}
		logger.Warnf("using the runner-side journal for %s; the target journal was never committed\n", profileID)
		return journal, nil
	}
	return loadRemoteJournal(client, profileID)
}

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

func RollbackSteps(client *remote.Client, steps []StepRecord) error {
	if err := ensureRollbackSudo(client); err != nil {
		return fmt.Errorf("sudo preflight failed: %w", err)
	}
	if err := preflightRollbackConflicts(client, steps, false, false); err != nil {
		return err
	}
	degraded, err := executeRollbackSteps(client, steps, false)
	if err != nil {
		return err
	}
	if len(degraded) > 0 {
		return fmt.Errorf("automatic rollback completed with degraded restoration:\n  %s", strings.Join(degraded, "\n  "))
	}
	return nil
}

func executeRollbackSteps(client *remote.Client, steps []StepRecord, showProgress bool) ([]string, error) {
	total := len(steps)
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
		stepDegraded, err := runRollbackOneStep(client, step, current, total, showProgress)
		degraded = append(degraded, stepDegraded...)
		if err != nil {
			return degraded, err
		}
	}

	for _, step := range deferredServiceSteps {
		current++
		stepDegraded, err := runRollbackOneStep(client, step, current, total, showProgress)
		degraded = append(degraded, stepDegraded...)
		if err != nil {
			return degraded, err
		}
	}
	return degraded, nil
}

func rollbackStepApplies(step StepRecord, all []StepRecord) bool {
	return stepActuallyChanged(step) || serviceReloadTriggered(step, all)
}

func preflightRollbackConflicts(client *remote.Client, steps []StepRecord, forceRollback, resuming bool) error {
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
		conflicts := checkStepConflicts(client, step, resuming)
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

func runRollbackOneStep(client *remote.Client, step StepRecord, current, total int, showProgress bool) ([]string, error) {
	if showProgress {
		logger.Infof("Reverting %02d/%02d %s [%s] ", current, total, step.ID, step.Type)
	}
	var stop func()
	start := rollbackNow()
	if showProgress {
		stop = utils.Throbber()
	}
	degraded, err := rollbackStepWithMode(client, step)
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

func checkStepConflicts(client *remote.Client, step StepRecord, resuming bool) []string {
	plug, ok := lookupPlugin(step.Type)
	if !ok {
		return nil
	}
	var beforeByKey map[string]pluginapi.ObjectRecord
	if resuming {
		beforeByKey = make(map[string]pluginapi.ObjectRecord, len(step.Before))
		for _, obj := range step.Before {
			beforeByKey[pluginapi.ObjectKey(obj)] = obj
		}
	}

	var conflicts []string
	for _, afterObj := range step.After {
		// An interrupted attempt leaves some objects back at Before and the rest still at After,
		// so an object already sitting at what this rollback would restore is progress, not drift.
		if beforeObj, paired := beforeByKey[pluginapi.ObjectKey(afterObj)]; paired &&
			len(plug.DetectConflict(client, beforeObj)) == 0 {
			continue
		}
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

func rollbackStepWithMode(client *remote.Client, step StepRecord) (degraded []string, err error) {
	if step.RollbackMode == pluginapi.ModeNoop {
		return nil, nil
	}

	plug, ok := lookupPlugin(step.Type)
	if !ok {
		return nil, fmt.Errorf("rollback step %q: plugin %q is not registered", step.ID, step.Type)
	}

	for i := len(step.Before) - 1; i >= 0; i-- {
		obj := step.Before[i]
		// A runtime policy records what a daemon held so the capture shows a delta; the plugin restores it through the file the daemon reads.
		if obj.Kind == pluginapi.ObjectRuntimePolicy {
			continue
		}
		rbErr := plug.Rollback(client, obj)
		if rbErr == nil {
			continue
		}
		if toleratesFailedRevert(step.RollbackMode) {
			logger.Warnf("rollback warning (%s, step=%s): %v\n", step.RollbackMode, step.ID, rbErr)
			degraded = append(degraded, fmt.Sprintf("step %q (%s): %v", step.ID, step.Type, rbErr))
			continue
		}
		return degraded, rbErr
	}

	return degraded, nil
}

// A step hardline never claimed it could revert faithfully reports a failed object as degraded instead of stranding the steps queued behind it.
func toleratesFailedRevert(mode string) bool {
	return mode == pluginapi.ModeBestEffort || mode == pluginapi.ModeIrreversible
}
