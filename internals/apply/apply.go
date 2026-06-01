package apply

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var applyNow = time.Now

const remoteApplyLockDir = "/var/lib/hardline/.apply-lock.d"

var (
	newSSHClient           = connection.NewSSHClient
	loadProfile            = profile.Load
	versionCmd             = cli.VersionCmd
	compareSemVer          = cli.CompareSemVer
	ensureApplySudo        = connection.EnsureNonInteractiveSudo
	ensureApplyPlugins     = pluginapi.EnsureProfilePlugins
	runApplyProfile        = applyProfile
	runCaptureStepRecord   = captureStepRecordWithRegistry
	runRollbackStep        = rollback.RollbackSteps
	saveRunnerJournal      = (*rollback.Journal).SaveLast
	removeRunnerJournal    = (*rollback.Journal).RemoveLast
	saveTargetJournal      = rollback.SaveRemoteLast
	runStep                = handleStepWithRegistry
	acquireRemoteApplyLock = defaultAcquireRemoteApplyLock
	releaseRemoteApplyLock = defaultReleaseRemoteApplyLock
)

func defaultAcquireRemoteApplyLock(client *remote.Client) error {
	if client == nil {
		return nil
	}
	cmd := "mkdir -p /var/lib/hardline && mkdir " + strconv.Quote(remoteApplyLockDir)
	if err := client.RunRoot(cmd); err != nil {
		return errors.New("another hardline apply is already running on this host; if stale, run: sudo rmdir " + remoteApplyLockDir)
	}
	return nil
}

func defaultReleaseRemoteApplyLock(client *remote.Client) error {
	if client == nil {
		return nil
	}
	return client.RunRoot("rmdir " + strconv.Quote(remoteApplyLockDir))
}

func Apply(ctx context.Context, c cli.Command) error {
	if !c.Debug {
		logger.Infof("apply %s\n", c.Profile)
	}

	logger.Debugf("apply: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
		Port:    c.Port,
	}

	sshClient, err := newSSHClient(*config)
	if err != nil {
		return logger.Wrap(err, "connect failed")
	}
	if sshClient != nil {
		defer sshClient.Close()
	}

	logger.Debugf("ssh connection established\n")

	if err := ensureApplySudo(sshClient); err != nil {
		return logger.Wrap(err, "sudo preflight failed")
	}

	if err := acquireRemoteApplyLock(sshClient); err != nil {
		return err
	}
	defer func() {
		if releaseErr := releaseRemoteApplyLock(sshClient); releaseErr != nil {
			logger.Warnf("release apply lock failed: %v\n", releaseErr)
		}
	}()

	p, err := loadProfile(c.Profile)
	if err != nil {
		return logger.Wrap(err, "profile load failed")
	}

	if err := connection.CheckRemoteOS(sshClient, p.OS.Family, p.OS.Version); err != nil {
		return logger.Wrap(err, "OS compatibility check failed")
	}

	logger.Debugf("profile loaded, starting applyProfile\n")

	ver, schemaVer, err := versionCmd()
	if err != nil {
		return logger.Wrap(err, "hardline version check failed")
	}

	cmp, err := compareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		return logger.Wrap(err, "invalid profile.min_hardline value "+strconv.Quote(p.MinHardline))
	}

	if cmp < 0 {
		return errors.New("hardline version " + ver.String() + " is too old; minimum required is " + p.MinHardline)
	}

	if p.ProfileSchema > schemaVer {
		return errors.New("profile schema " + strconv.Itoa(p.ProfileSchema) + " is newer than supported " + strconv.Itoa(schemaVer) + "; please upgrade hardline")
	}

	if err := p.Affirm(); err != nil {
		return logger.Wrap(err, "profile validation failed")
	}
	if err := ensureApplyPlugins(registry.Shared(), p); err != nil {
		return logger.Wrap(err, "required plugin validation failed")
	}

	overrides, err := cli.ResolveOverrides(c)
	if err != nil {
		return logger.Wrap(err, "resolve runtime overrides failed")
	}
	if err := p.ValidateOverrides(overrides); err != nil {
		return logger.Wrap(err, "profile override validation failed")
	}
	p.SetRuntimeOverrides(overrides)

	journal := rollback.NewJournal(c.Host, p.ID, c.Profile)
	if err := saveRunnerJournal(journal); err != nil {
		return logger.Wrap(err, "persist local rollback journal failed")
	}

	if err := runApplyProfile(ctx, sshClient, p, journal); err != nil {
		journal.Status = "failed"
		if saveErr := saveRunnerJournal(journal); saveErr != nil {
			return errors.New(err.Error() + "; persist local rollback journal failed: " + saveErr.Error())
		}
		return err
	}

	journal.Status = "success"
	if err := saveTargetJournal(sshClient, journal); err != nil {
		_ = saveRunnerJournal(journal)
		return logger.Wrap(err, "persist target rollback journal failed")
	}
	if c.KeepLocalRollback {
		if err := saveRunnerJournal(journal); err != nil {
			logger.Warnf("keep local rollback journal failed: %v\n", err)
		}
	} else if err := removeRunnerJournal(journal); err != nil {
		logger.Warnf("remove local rollback journal failed: %v\n", err)
	}

	logger.Debugf("apply completed\n")
	return nil
}

func applyProfile(ctx context.Context, client *remote.Client, p *profile.Profile, journal *rollback.Journal) error {
	logger.Debugf("applyProfile: %d action files\n", len(p.ActionFiles))

	stepChanges := make(map[string]bool)
	totalSteps := countApplySteps(p)
	currentStep := 0
	changedCount := 0
	alignedCount := 0
	runStart := applyNow()

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			select {
			case <-ctx.Done():
				if journal != nil {
					journal.Status = "interrupted"
					_ = saveRunnerJournal(journal)
					if len(journal.Steps) > 0 {
						_ = runRollbackStep(client, journal.Steps)
					}
				}
				return logger.Wrap(ctx.Err(), "interrupted")
			default:
			}

			currentStep++
			logger.Infof("Applying %02d/%02d %s [%s] ", currentStep, totalSteps, step.ID, step.PluginName())
			logger.Debugf("handleStep: id=%q type=%q\n", step.ID, step.PluginName())

			stepStart := applyNow()
			stop := utils.Throbber()
			err := executeStep(client, p, step, journal, stepChanges)
			if stop != nil {
				stop()
			}
			duration := applyNow().Sub(stepStart)

			if err != nil {
				logger.Infof("%s✗ FAILED%s (%s)\n", logger.ColorRed+logger.ColorBold, logger.ColorReset, formatShortDuration(duration))
				if journal != nil {
					rbErr := runRollbackStep(client, journal.Steps)
					if rbErr != nil {
						return errors.New("step " + strconv.Quote(step.ID) + " failed: " + err.Error() + "; automatic rollback failed: " + rbErr.Error())
					}
					return errors.New("step " + strconv.Quote(step.ID) + " failed: " + err.Error() + "; automatic rollback completed")
				}
				return err
			}

			if stepChanges[step.ID] {
				changedCount++
				logger.Infof("%s✓ CHANGED%s (%s)\n", logger.ColorBlue+logger.ColorBold, logger.ColorReset, formatShortDuration(duration))
			} else {
				alignedCount++
				logger.Infof("%s✓ ALIGNED%s (%s)\n", logger.ColorGreen+logger.ColorBold, logger.ColorReset, formatShortDuration(duration))
			}
		}
	}

	writeApplyFooter(p, journal, totalSteps, changedCount, alignedCount, applyNow().Sub(runStart))
	return nil
}

func countApplySteps(p *profile.Profile) int {
	if p == nil {
		return 0
	}
	total := 0
	for _, af := range p.ActionFiles {
		total += len(af.Steps)
	}
	return total
}

func writeApplyFooter(p *profile.Profile, journal *rollback.Journal, total, changed, aligned int, duration time.Duration) {
	var b strings.Builder
	row := func(label, value string) {
		b.WriteString(label)
		b.WriteString(value)
		b.WriteString("\n")
	}

	b.WriteString("\n" + logger.ColorCyan + logger.ColorBold + "APPLY COMPLETE" + logger.ColorReset + "\n")
	row("", strings.Repeat("-", 60))
	if p != nil {
		row(logger.ColorBold+"Profile"+logger.ColorReset+"  : ", p.DisplayName)
		row(logger.ColorBold+"Version"+logger.ColorReset+"  : ", p.Version)
	}
	row(logger.ColorBold+"Steps"+logger.ColorReset+"    : ", strconv.Itoa(total))
	row(logger.ColorBold+"Changed"+logger.ColorReset+"  : ", logger.ColorBlue+strconv.Itoa(changed)+logger.ColorReset)
	row(logger.ColorBold+"Aligned"+logger.ColorReset+"  : ", logger.ColorGreen+strconv.Itoa(aligned)+logger.ColorReset)
	row(logger.ColorBold+"Duration"+logger.ColorReset+" : ", formatShortDuration(duration))

	rollbackStatus := "AVAILABLE (on target)"
	if journal != nil && journal.RunID != "" {
		rollbackStatus = "AVAILABLE (run " + journal.RunID + ")"
	}
	row(logger.ColorBold+"Rollback"+logger.ColorReset+" : ", logger.ColorGreen+rollbackStatus+logger.ColorReset)
	b.WriteString("\n")

	logger.Infof("%s", b.String())
}

// formatShortDuration renders a Duration in a compact human-readable form:
// sub-second → "423ms", sub-minute → "4.7s", minute+ → "5m18s".
func formatShortDuration(d time.Duration) string {
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

func executeStep(client *remote.Client, p *profile.Profile, step profile.Step, journal *rollback.Journal, stepChanges map[string]bool) error {
	beforeCapture, err := runCaptureStepRecord(registry.Shared(), client, p, step)
	if err != nil {
		return err
	}

	if journal != nil {
		stepRecord := rollback.NewStepRecordFromCapture(step.ID, step.PluginName(), beforeCapture)
		journal.Steps = append(journal.Steps, stepRecord)
		if err := saveRunnerJournal(journal); err != nil {
			return logger.Wrap(err, "persist local rollback journal failed")
		}
	}

	if err := runStep(registry.Shared(), client, p, step, stepChanges); err != nil {
		return err
	}

	if journal == nil {
		return nil
	}

	afterCapture, err := runCaptureStepRecord(registry.Shared(), client, p, step)
	if err != nil {
		return logger.Wrap(err, "capture post-apply state for step "+strconv.Quote(step.ID))
	}

	// Record the actual outcome for downstream steps (service restart on_change)
	stepChanges[step.ID] = pluginapi.CapturesDiffer(beforeCapture, afterCapture)
	journal.Steps[len(journal.Steps)-1].SetAfterFromCapture(afterCapture)
	if err := saveRunnerJournal(journal); err != nil {
		return logger.Wrap(err, "persist local rollback journal failed")
	}
	return nil
}
