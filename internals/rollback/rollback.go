package rollback

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

var rollbackNow = time.Now

var (
	newSSHClient       = connection.NewSSHClient
	runRootCmd         = (*remote.Client).RunRoot
	writeRootFile      = (*remote.Client).WriteRootFile
	ensureRollbackSudo = connection.EnsureNonInteractiveSudo
	runRollbackCommand = rollbackCommand
	loadRemoteJournal  = func(client *remote.Client, profileID string) (*Journal, error) {
		return LoadRemoteLast(client, profileID)
	}
	deleteJournal = func(client *remote.Client, profileID, runID string) error {
		return DeleteRemoteJournal(client, profileID, runID)
	}
	readRemoteFile       = (*remote.Client).ReadRootFile
	runRootWithOutputCmd = (*remote.Client).RunRootWithOutput
	loadProfileID        = defaultLoadProfileID
	exitProcess          = os.Exit
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
	b.WriteString("\n")
	b.WriteString(logger.ColorCyan + logger.ColorBold + "ROLLBACK COMPLETE" + logger.ColorReset + "\n")
	b.WriteString(strings.Repeat("-", 60) + "\n")
	if journal != nil {
		b.WriteString(logger.ColorBold + "Profile" + logger.ColorReset + "  : " + journal.ProfileID + "\n")
		if journal.RunID != "" {
			b.WriteString(logger.ColorBold + "Run ID" + logger.ColorReset + "   : " + journal.RunID + "\n")
		}
		b.WriteString(logger.ColorBold + "Steps" + logger.ColorReset + "    : " + strconv.Itoa(len(journal.Steps)) + "\n")
	}
	b.WriteString(logger.ColorBold + "Duration" + logger.ColorReset + " : " + formatRollbackDuration(duration) + "\n\n")
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

// checkStepConflicts reads the current remote state for each object in a step and
// compares it against the journal's after snapshot. If they differ, another profile or
// manual edit changed the state after this profile ran. Returns one message per conflict.
func checkStepConflicts(client *remote.Client, step StepRecord) []string {
	var conflicts []string
	for _, afterObj := range step.After {
		switch afterObj.Kind {
		case pluginapi.ObjectFile:
			if afterObj.File == nil {
				continue
			}
			snap := afterObj.File
			// If this profile deleted the file (after.Existed=false), nothing to compare.
			if !snap.Existed {
				continue
			}
			// Decode the content the journal recorded as the post-apply state.
			expectedContent, err := base64.StdEncoding.DecodeString(snap.ContentB64)
			if err != nil {
				// Malformed ContentB64 in journal — skip conflict check for this object.
				continue
			}
			current, err := readRemoteFile(client, snap.Path)
			if err != nil {
				conflicts = append(conflicts, fmt.Sprintf("%s: journal expects file to exist but it cannot be read (%v)", snap.Path, err))
				continue
			}
			if current != string(expectedContent) {
				conflicts = append(conflicts, fmt.Sprintf("%s: current content differs from what this profile wrote (modified since apply)", snap.Path))
			}

		case pluginapi.ObjectService:
			if afterObj.Service == nil {
				continue
			}
			snap := afterObj.Service
			if !snap.Known {
				continue
			}
			unit := strings.TrimSpace(snap.Unit)
			if unit == "" {
				continue
			}
			currentEnabled := runRootCmd(client, "systemctl is-enabled "+strconv.Quote(unit)+" >/dev/null 2>&1") == nil
			currentActive := runRootCmd(client, "systemctl is-active "+strconv.Quote(unit)+" >/dev/null 2>&1") == nil
			if currentEnabled != snap.Enabled {
				conflicts = append(conflicts, fmt.Sprintf("service %q: enabled state is %v but journal recorded %v after apply (changed since apply)", unit, currentEnabled, snap.Enabled))
			}
			if currentActive != snap.Active {
				conflicts = append(conflicts, fmt.Sprintf("service %q: active state is %v but journal recorded %v after apply (changed since apply)", unit, currentActive, snap.Active))
			}

		case pluginapi.ObjectPackage:
			if afterObj.Package == nil {
				continue
			}
			snap := afterObj.Package
			name := strings.TrimSpace(snap.Name)
			if name == "" {
				continue
			}
			currentInstalled := runRootCmd(client, "dpkg -s "+strconv.Quote(name)+" >/dev/null 2>&1") == nil
			if currentInstalled != snap.WasInstalled {
				conflicts = append(conflicts, fmt.Sprintf("package %q: installed=%v but journal recorded installed=%v after apply (changed since apply)", name, currentInstalled, snap.WasInstalled))
			} else if currentInstalled && snap.WasInstalled && snap.Version != "" {
				currentVersion := queryPackageVersion(client, name)
				if currentVersion != "" && currentVersion != snap.Version {
					conflicts = append(conflicts, fmt.Sprintf("package %q: version is %q but journal recorded %q after apply (upgraded since apply)", name, currentVersion, snap.Version))
				}
			}
		}
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

	for i := len(step.Before) - 1; i >= 0; i-- {
		obj := step.Before[i]
		err := rollbackObject(client, obj)
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

func rollbackObject(client *remote.Client, obj pluginapi.ObjectRecord) error {
	switch obj.Kind {
	case pluginapi.ObjectFile:
		if obj.File == nil {
			return fmt.Errorf("file rollback object missing snapshot payload")
		}
		return restoreFile(client, *obj.File)
	case pluginapi.ObjectService:
		if obj.Service == nil {
			return fmt.Errorf("service rollback object missing snapshot payload")
		}
		return restoreService(client, *obj.Service)
	case pluginapi.ObjectPackage:
		if obj.Package == nil {
			return fmt.Errorf("package rollback object missing snapshot payload")
		}
		return rollbackPackageBestEffort(client, *obj.Package)
	case pluginapi.ObjectValidate:
		return nil
	default:
		return fmt.Errorf("unsupported rollback object kind %q", obj.Kind)
	}
}

func restoreFile(client *remote.Client, snap pluginapi.FileSnapshot) error {
	if err := pluginapi.EnforceManagedPath(snap.Path); err != nil {
		return err
	}

	if !snap.Existed {
		return runRootCmd(client, "rm -f "+strconv.Quote(snap.Path))
	}

	mode := os.FileMode(0o600)
	if strings.TrimSpace(snap.Mode) != "" {
		if parsed, err := strconv.ParseUint(strings.TrimSpace(snap.Mode), 8, 32); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	content, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("decode snapshot content for %q: %w", snap.Path, err)
	}

	dir := path.Dir(snap.Path)
	if dir != "" && dir != "." {
		if err := runRootCmd(client, "mkdir -p "+strconv.Quote(dir)); err != nil {
			return fmt.Errorf("ensure directory %q: %w", dir, err)
		}
	}

	if err := writeRootFile(client, snap.Path, content, mode); err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
	}
	return nil
}

func restoreService(client *remote.Client, state pluginapi.ServiceState) error {
	unit := strings.TrimSpace(state.Unit)
	if unit == "" {
		return fmt.Errorf("service unit is empty")
	}
	if !state.Known {
		return fmt.Errorf("service state for %q is unknown", unit)
	}

	enableCmd := "systemctl disable " + strconv.Quote(unit)
	if state.Enabled {
		enableCmd = "systemctl enable " + strconv.Quote(unit)
	}
	if err := runRootCmd(client, enableCmd); err != nil {
		return fmt.Errorf("restore service enabled state for %q: %w", unit, err)
	}

	activeCmd := "systemctl stop " + strconv.Quote(unit)
	if state.Active {

		activeCmd = "systemctl restart " + strconv.Quote(unit)
	}
	if err := runRootCmd(client, activeCmd); err != nil {
		return fmt.Errorf("restore service active state for %q: %w", unit, err)
	}
	return nil
}

func rollbackPackageBestEffort(client *remote.Client, p pluginapi.PackageState) error {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return fmt.Errorf("package name is empty")
	}

	if p.RequestedInstall && !p.WasInstalled {
		if err := runRootCmd(client, "apt-get purge -y "+strconv.Quote(name)); err != nil {
			return fmt.Errorf("purge package %q: %w", name, err)
		}
	}

	if p.RequestedPurge && p.WasInstalled {
		if p.Version != "" {
			withVersion := name + "=" + p.Version
			if err := runRootCmd(client, "DEBIAN_FRONTEND=noninteractive apt-get install -y "+strconv.Quote(withVersion)); err == nil {
				return nil
			}
		}
		if err := runRootCmd(client, "DEBIAN_FRONTEND=noninteractive apt-get install -y "+strconv.Quote(name)); err != nil {
			return fmt.Errorf("reinstall package %q: %w", name, err)
		}
	}

	return nil
}

func queryPackageVersion(client *remote.Client, name string) string {
	out, err := runRootWithOutputCmd(client, "dpkg-query -W -f='${Version}' "+strconv.Quote(name)+" 2>/dev/null")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
