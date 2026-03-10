package template

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/rollbackutil"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ApplyDeps struct {
	RunRoot       func(*ssh.Client, string) error
	NewSFTPClient func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

func Apply(ctx pluginapi.ApplyContext, t *Spec, deps ApplyDeps) error {
	logger.Debugf("handleTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	if ctx.Profile == nil {
		return fmt.Errorf("template step: profile context is required")
	}

	data, err := ctx.Profile.LoadTemplate(t.Src)
	if err != nil {
		return fmt.Errorf("load template %q: %w", t.Src, err)
	}

	sftpClient, err := deps.NewSFTPClient(ctx.Client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	mode := os.FileMode(0600)
	if t.Mode != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	dir := path.Dir(t.Dest)
	if dir != "" && dir != "." {
		if err := deps.RunRoot(ctx.Client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	if err := deps.WriteRootFile(ctx.Client, sftpClient, t.Dest, data, mode); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", t.Dest, err)
	}

	return nil
}

func Plan(ctx pluginapi.PlanContext, t *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	if ctx.Profile == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("template step: profile context is required")
	}

	rendered, err := ctx.Profile.LoadTemplate(t.Src)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("load template %q: %w", t.Src, err)
	}

	var details []string

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

	info, err := ctx.Runtime.Stat(t.Dest)
	if err != nil {
		line := fmt.Sprintf(
			"%sdestination %q:%s %sdoes not exist (file will be created)%s",
			logger.ColorBlue, t.Dest, logger.ColorReset,
			logger.ColorGreen, logger.ColorReset,
		)
		details = append(details, line)
	} else {
		exists = true
		line := fmt.Sprintf(
			"%sdestination %q:%s %sexists (size=%d bytes, mode=%#o)%s",
			logger.ColorBlue, t.Dest, logger.ColorReset,
			logger.ColorYellow, info.Size(), info.Mode().Perm(), logger.ColorReset,
		)
		details = append(details, line)
		modeMatches = info.Mode().Perm() == mode.Perm()
		if modeMatches {
			details = append(details,
				logger.ColorGreen+fmt.Sprintf("destination mode matches desired mode %#o", mode.Perm())+logger.ColorReset,
			)
		} else {
			details = append(details,
				logger.ColorYellow+fmt.Sprintf("destination mode differs (current=%#o desired=%#o)", info.Mode().Perm(), mode.Perm())+logger.ColorReset,
			)
		}

		current, readErr := ctx.Runtime.ReadRootFile(t.Dest)
		if readErr != nil {
			details = append(details,
				logger.ColorRed+fmt.Sprintf("cannot compare content for %q (%v)", t.Dest, readErr)+logger.ColorReset,
			)
		} else {
			compareReady = true
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
	}

	details = append(details,
		logger.ColorGreen+fmt.Sprintf("desired: template %q rendered to %q with mode %s", t.Src, t.Dest, modeText)+logger.ColorReset,
	)

	summary := fmt.Sprintf("template step: render %q to %q (mode %s)", t.Src, t.Dest, modeText)
	if exists && compareReady && modeMatches && contentMatches {
		summary = fmt.Sprintf("template step: no rewrite required for %q (content and mode already match)", t.Dest)
		details = append(details,
			logger.ColorGreen+"rewrite decision: no rewrite required"+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorYellow+"rewrite decision: rewrite required"+logger.ColorReset,
		)
	}
	return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
}

func CaptureRollback(ctx pluginapi.RollbackContext, stepID string, spec *Spec, deps RollbackDeps) (rollback.StepRecord, error) {
	record := rollback.StepRecord{
		ID:   stepID,
		Type: "template",
	}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=template): template spec missing", stepID)
	}

	dest := strings.TrimSpace(spec.Dest)
	if err := rollbackutil.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=template): %w", stepID, err)
	}

	snap, err := rollbackutil.SnapshotRemoteFile(ctx.Client, dest, rollbackutil.Deps{
		RunRoot:           deps.RunRoot,
		RunRootWithOutput: deps.RunRootWithOutput,
		ReadRootFile:      deps.ReadRootFile,
	})
	if err != nil {
		return record, fmt.Errorf("capture template snapshot for %q: %w", dest, err)
	}

	record.RollbackMode = rollback.ModeDeterministic
	record.Objects = []rollback.ObjectRecord{
		{Kind: rollback.ObjectFile, File: &snap},
	}
	return record, nil
}
