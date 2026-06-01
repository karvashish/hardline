package rollback

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/utils"
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
	lookupPlugin  = registry.Shared().Lookup
	loadProfileID = defaultLoadProfileID
	exitProcess   = os.Exit
)

func Rollback(c cli.Command) {
	if err := runRollbackCommand(c); err != nil {
		logger.Errorf("rollback failed: %v\n", err)
		exitProcess(1)
	}
}

func rollbackCommand(c cli.Command) error {
	logger.Infof("rollback %s\n", c.Profile)
	runStart := rollbackNow()

	profileID, err := loadProfileID(c.Profile)
	if err != nil {
		return fmt.Errorf("load profile ID: %w", err)
	}

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

	journal, err := loadRemoteJournal(client, profileID)
	if err != nil {
		return err
	}
	if journal.Status != "success" {
		return fmt.Errorf("last run is not marked successful (status=%q)", journal.Status)
	}

	if data, err := marshalJournal(journal); err == nil {
		logger.Infof("journal %s (run %s applied %s):\n%s\n", profileID, journal.RunID, journal.CreatedAt, string(data))
	}

	if err := executeRollbackSteps(client, journal.Steps, true, false, c.ForceRollback); err != nil {
		return err
	}

	if err := deleteJournal(client, journal.ProfileID, journal.RunID); err != nil {
		logger.Warnf("warning: could not delete remote journal %q: %v\n", journal.RunID, err)
	}

	writeRollbackFooter(journal, rollbackNow().Sub(runStart))
	return nil
}

func writeRollbackFooter(journal *Journal, duration time.Duration) {
	var b strings.Builder
	row := func(label, value string) {
		b.WriteString(label)
		b.WriteString(value)
		b.WriteString("\n")
	}

	b.WriteString("\n" + logger.ColorCyan + logger.ColorBold + "ROLLBACK COMPLETE" + logger.ColorReset + "\n")
	row("", strings.Repeat("-", 60))
	if journal != nil {
		row(logger.ColorBold+"Profile"+logger.ColorReset+"  : ", journal.ProfileID)
		if journal.RunID != "" {
			row(logger.ColorBold+"Run ID"+logger.ColorReset+"   : ", journal.RunID)
		}
		row(logger.ColorBold+"Steps"+logger.ColorReset+"    : ", strconv.Itoa(len(journal.Steps)))
	}
	row(logger.ColorBold+"Duration"+logger.ColorReset+" : ", formatRollbackDuration(duration))
	b.WriteString("\n")
	logger.Infof("%s", b.String())
}

func defaultLoadProfileID(profilePath string) (string, error) {
	data, err := os.ReadFile(filepath.Join(profilePath, "profile.json"))
	if err != nil {
		return "", fmt.Errorf("read profile.json: %w", err)
	}
	var manifest struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", fmt.Errorf("parse profile.json: %w", err)
	}
	if strings.TrimSpace(manifest.ID) == "" {
		return "", fmt.Errorf("profile.json missing id field")
	}
	return strings.TrimSpace(manifest.ID), nil
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

func RollbackSteps(client *remote.Client, steps []StepRecord) error {
	if err := ensureRollbackSudo(client); err != nil {
		return fmt.Errorf("sudo preflight failed: %w", err)
	}
	return executeRollbackSteps(client, steps, false, false, false)
}

func executeRollbackSteps(client *remote.Client, steps []StepRecord, showProgress bool, strictBestEffort bool, forceRollback bool) error {
	total := countRollbackSteps(steps)
	var deferredServiceSteps []StepRecord
	deferred := 0
	current := 0

	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if !stepActuallyChanged(step) {
			current++
			if showProgress {
				logger.Infof("Reverting %02d/%02d %s [%s] %sSKIPPED%s (no delta)\n",
					current, total, step.ID, step.Type,
					logger.ColorDim, logger.ColorReset)
			}
			continue
		}
		conflicts := checkStepConflicts(client, step)
		if len(conflicts) > 0 {
			msg := fmt.Sprintf("step %q: files were modified after this profile ran — rolling back will overwrite those changes:\n", step.ID)
			for _, c := range conflicts {
				msg += "  " + c + "\n"
			}
			if !forceRollback {
				return fmt.Errorf("%sre-run with --force-rollback to overwrite", msg)
			}
			logger.Warnf("WARNING: %s--force-rollback set, proceeding anyway\n", msg)
		}
		if stepHasServiceObjects(step) {
			deferredServiceSteps = append(deferredServiceSteps, step)
			deferred++
			continue
		}
		current++
		if err := runRollbackOneStep(client, step, current, total, showProgress, strictBestEffort); err != nil {
			return err
		}
	}

	for _, step := range deferredServiceSteps {
		current++
		if err := runRollbackOneStep(client, step, current, total, showProgress, strictBestEffort); err != nil {
			return err
		}
	}
	return nil
}

func runRollbackOneStep(client *remote.Client, step StepRecord, current, total int, showProgress, strictBestEffort bool) error {
	if showProgress {
		logger.Infof("Reverting %02d/%02d %s [%s] ", current, total, step.ID, step.Type)
	}
	var stop func()
	start := rollbackNow()
	if showProgress {
		stop = utils.Throbber()
	}
	err := rollbackStepWithMode(client, step, strictBestEffort)
	if stop != nil {
		stop()
	}
	duration := rollbackNow().Sub(start)
	if err != nil {
		if showProgress {
			logger.Infof("%s✗ FAILED%s (%s)\n", logger.ColorRed+logger.ColorBold, logger.ColorReset, formatRollbackDuration(duration))
		}
		return fmt.Errorf("rollback step %q failed: %w", step.ID, err)
	}
	if showProgress {
		logger.Infof("%s✓ REVERTED%s (%s)\n", logger.ColorGreen+logger.ColorBold, logger.ColorReset, formatRollbackDuration(duration))
	}
	return nil
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

func rollbackStepWithMode(client *remote.Client, step StepRecord, strictBestEffort bool) error {
	if step.RollbackMode == pluginapi.ModeNoop {
		return nil
	}

	plug, ok := lookupPlugin(step.Type)
	if !ok {
		return fmt.Errorf("rollback step %q: plugin %q is not registered", step.ID, step.Type)
	}

	for i := len(step.Before) - 1; i >= 0; i-- {
		obj := step.Before[i]
		err := plug.Rollback(client, obj)
		if err == nil {
			continue
		}
		if step.RollbackMode == pluginapi.ModeBestEffort && !strictBestEffort {
			logger.Warnf("rollback warning (best-effort, step=%s): %v\n", step.ID, err)
			continue
		}
		return err
	}

	return nil
}
