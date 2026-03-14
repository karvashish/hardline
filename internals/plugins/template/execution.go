package template

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/rollbackutil"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ApplyDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
	NewSFTPClient     func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile     func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

type templateStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type templateCompareRuntime interface {
	templateStatRuntime
	ReadRootFile(path string) (string, error)
}

type applyRuntime struct {
	client *ssh.Client
	deps   ApplyDeps
}

func (r applyRuntime) RunRoot(cmd string) error {
	return r.deps.RunRoot(r.client, cmd)
}

func (r applyRuntime) RunRootWithOutput(cmd string) (string, error) {
	return r.deps.RunRootWithOutput(r.client, cmd)
}

func (r applyRuntime) ReadRootFile(path string) (string, error) {
	return r.deps.ReadRootFile(r.client, path)
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

	mode := os.FileMode(0600)
	if t.Mode != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	if canCompareTemplateDestination(deps) {
		matches, err := templateDestinationMatches(applyRuntime{client: ctx.Client, deps: deps}, t.Dest, data, mode)
		if err != nil {
			return fmt.Errorf("compare destination %s: %w", t.Dest, err)
		}
		if matches {
			logger.Debugf("handleTemplate: destination %q already matches, skipping write\n", t.Dest)
			return nil
		}
	}

	dir := path.Dir(t.Dest)
	if dir != "" && dir != "." {
		if err := deps.RunRoot(ctx.Client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	sftpClient, err := deps.NewSFTPClient(ctx.Client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := deps.WriteRootFile(ctx.Client, sftpClient, t.Dest, data, mode); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", t.Dest, err)
	}

	return nil
}

func canCompareTemplateDestination(deps ApplyDeps) bool {
	return deps.RunRoot != nil && deps.RunRootWithOutput != nil && deps.ReadRootFile != nil
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

	size, currentMode, err := statTemplateDestination(ctx.Runtime, t.Dest)
	if err != nil {
		details = append(details,
			logger.ColorRed+fmt.Sprintf("cannot stat destination %q (%v)", t.Dest, err)+logger.ColorReset,
		)
	} else if size < 0 {
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

func statTemplateDestination(rt templateStatRuntime, dest string) (int64, os.FileMode, error) {
	if rt == nil {
		return 0, 0, fmt.Errorf("runtime is required")
	}
	if err := rt.RunRoot(fmt.Sprintf("test -e %s", strconv.Quote(dest))); err != nil {
		return -1, 0, nil
	}

	out, err := rt.RunRootWithOutput(fmt.Sprintf("stat -c '%%a %%s' -- %s", strconv.Quote(dest)))
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
