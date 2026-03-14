package apply

import (
	"fmt"
	"os"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/connection"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/internals/utils"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

var (
	newSSHClient         = connection.NewSSHClient
	loadProfile          = profile.Load
	versionCmd           = cli.VersionCmd
	compareSemVer        = cli.CompareSemVer
	ensureApplySudo      = connection.EnsureNonInteractiveSudo
	ensureApplyPlugins   = registry.EnsureProfilePlugins
	runApplyProfile      = applyProfile
	runCaptureStepRecord = captureStepRecord
	runRollbackStep      = rollback.RollbackSteps
	runApplyCommand      = applyCommand
	saveRunnerJournal    = func(j *rollback.Journal) error { return j.SaveLast() }
	removeRunnerJournal  = func(j *rollback.Journal) error { return j.RemoveLast() }
	saveTargetJournal    = rollback.SaveRemoteLast
	exitProcess          = os.Exit
	runStep              = handleStep
)

func Apply(c cli.Command) {
	if err := runApplyCommand(c); err != nil {
		exitProcess(1)
	}
}

func applyCommand(c cli.Command) error {
	if !c.Debug {
		logger.Infof("apply %s\n", c.Profile)
	}

	logger.Debugf("apply: profile=%q host=%q user=%q key=%q\n", c.Profile, c.Host, c.User, c.KeyPath)

	config := &connection.Config{
		User:    c.User,
		KeyPath: c.KeyPath,
		Host:    c.Host,
	}

	sshClient, err := newSSHClient(*config)
	if err != nil {
		logger.Errorf("connect failed: %v\n", err)
		return fmt.Errorf("connect failed: %w", err)
	}
	if sshClient != nil {
		defer sshClient.Close()
	}

	logger.Debugf("ssh connection established\n")

	if err := ensureApplySudo(sshClient); err != nil {
		logger.Errorf("sudo preflight failed: %v\n", err)
		return fmt.Errorf("sudo preflight failed: %w", err)
	}

	p, err := loadProfile(c.Profile)
	if err != nil {
		logger.Errorf("profile load failed: %v\n", err)
		return fmt.Errorf("profile load failed: %w", err)
	}

	logger.Debugf("profile loaded, starting applyProfile\n")

	ver, schemaVer, err := versionCmd()
	if err != nil {
		logger.Errorf("hardline version check failed: %v\n", err)
		return fmt.Errorf("hardline version check failed: %w", err)
	}

	cmp, err := compareSemVer(ver.String(), p.MinHardline)
	if err != nil {
		logger.Errorf("invalid profile.min_hardline value %q: %v\n", p.MinHardline, err)
		return fmt.Errorf("invalid profile.min_hardline value %q: %w", p.MinHardline, err)
	}

	if cmp < 0 {
		logger.Errorf(
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
		return fmt.Errorf(
			"hardline version %s is too old; minimum required is %s\n",
			ver.String(), p.MinHardline,
		)
	}

	if p.ProfileSchema > schemaVer {
		logger.Errorf(
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
		return fmt.Errorf(
			"profile schema %d is newer than supported %d; please upgrade hardline\n",
			p.ProfileSchema, schemaVer,
		)
	}

	if err := p.Affirm(); err != nil {
		logger.Errorf("profile validation failed: %v\n", err)
		return fmt.Errorf("profile validation failed: %w", err)
	}
	if err := ensureApplyPlugins(p); err != nil {
		logger.Errorf("required plugin validation failed: %v\n", err)
		return fmt.Errorf("required plugin validation failed: %w", err)
	}

	journal := rollback.NewJournal(c.Host, p.ID, c.Profile)
	if err := saveRunnerJournal(journal); err != nil {
		logger.Errorf("persist local rollback journal failed: %v\n", err)
		return fmt.Errorf("persist local rollback journal failed: %w", err)
	}

	if err := runApplyProfile(sshClient, p, journal); err != nil {
		journal.Status = "failed"
		if saveErr := saveRunnerJournal(journal); saveErr != nil {
			logger.Errorf("persist local rollback journal failed: %v\n", saveErr)
			return fmt.Errorf("apply failed: %w; persist local rollback journal failed: %v", err, saveErr)
		}
		logger.Errorf("apply failed: %v\n", err)
		return fmt.Errorf("apply failed: %w", err)
	}

	journal.Status = "success"
	if err := saveTargetJournal(sshClient, journal); err != nil {
		_ = saveRunnerJournal(journal)
		logger.Errorf("persist target rollback journal failed: %v\n", err)
		return fmt.Errorf("persist target rollback journal failed: %w", err)
	}
	if c.KeepLocalRollback {
		if err := saveRunnerJournal(journal); err != nil {
			logger.Warnf("keep local rollback journal failed: %v\n", err)
		}
	} else if err := removeRunnerJournal(journal); err != nil {
		logger.Warnf("remove local rollback journal failed: %v\n", err)
	}

	if !c.Debug {
		logger.Infof("ok\n")
	}

	logger.Debugf("apply completed\n")
	return nil
}

func applyProfile(client *ssh.Client, p *profile.Profile, journal *rollback.Journal) error {
	logger.Debugf("applyProfile: %d action files\n", len(p.ActionFiles))
	resetApplyStepState()

	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if !logger.DebugMode() {
				logger.Infof("step: %s (%s) ", step.ID, step.PluginName())
			}
			logger.Debugf("handleStep: id=%q type=%q\n", step.ID, step.PluginName())

			var stop func()
			if !logger.DebugMode() {
				stop = utils.Throbber()
			}

			capture, err := runCaptureStepRecord(client, p, step)
			if err != nil {
				if stop != nil {
					stop()
				}
				return err
			}

			if journal != nil {
				stepRecord := rollback.NewStepRecordFromCapture(step.ID, step.PluginName(), capture)
				journal.Steps = append(journal.Steps, stepRecord)
				if err := saveRunnerJournal(journal); err != nil {
					if stop != nil {
						stop()
					}
					return fmt.Errorf("persist local rollback journal failed: %w", err)
				}
			}

			err = runStep(client, p, step)
			if err == nil && journal != nil {
				capture, captureErr := runCaptureStepRecord(client, p, step)
				if captureErr != nil {
					err = fmt.Errorf("capture post-apply state for step %q: %w", step.ID, captureErr)
				} else {
					journal.Steps[len(journal.Steps)-1].SetAfterFromCapture(capture)
					if saveErr := saveRunnerJournal(journal); saveErr != nil {
						err = fmt.Errorf("persist local rollback journal failed: %w", saveErr)
					}
				}
			}

			if err != nil {
				if stop != nil {
					stop()
				}
				if journal != nil {
					rbErr := runRollbackStep(client, journal.Steps)
					if rbErr != nil {
						return fmt.Errorf("step %q failed: %w; automatic rollback failed: %v", step.ID, err, rbErr)
					}
					return fmt.Errorf("step %q failed: %w; automatic rollback completed", step.ID, err)
				}
				return err
			}
			if stop != nil {
				stop()
			}

			if !logger.DebugMode() {
				logger.Infof("✓\n")
			}
		}
	}
	return nil
}
