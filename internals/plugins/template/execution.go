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
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type ApplyDeps struct {
	RunRoot          func(*ssh.Client, string) error
	NewSFTPClient    func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile    func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
	MarkServiceDirty func(string)
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

func Apply(ctx pluginapi.ApplyContext, t *profile.TemplateSpec, deps ApplyDeps) error {
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
	if deps.MarkServiceDirty != nil {
		deps.MarkServiceDirty(serviceForManagedPath(t.Dest))
	}

	return nil
}

func Plan(ctx pluginapi.PlanContext, t *profile.TemplateSpec) (pluginapi.PlanResult, error) {
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

	info, err := ctx.Inspector.Stat(t.Dest)
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

		current, readErr := ctx.Inspector.ReadRootFile(t.Dest)
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

	if strings.HasPrefix(t.Dest, "/etc/ssh/") {
		details = append(details, logger.ColorDim+"note: this template affects SSH daemon configuration"+logger.ColorReset)
	}
	if strings.Contains(t.Dest, "nftables") {
		details = append(details, logger.ColorDim+"note: this template affects nftables firewall configuration"+logger.ColorReset)
	}

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

func ValidateApply(ctx pluginapi.ApplyContext, runRoot func(*ssh.Client, string) error) error {
	checkIncludeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config`
	if err := runRoot(ctx.Client, checkIncludeCmd); err != nil {
		return fmt.Errorf("sshd_config missing Include for /etc/ssh/sshd_config.d/*.conf: %w", err)
	}

	if err := runRoot(ctx.Client, "sshd -t -f /etc/ssh/sshd_config"); err != nil {
		return fmt.Errorf("sshd config test failed: %w", err)
	}
	return nil
}

func ValidatePlan(ctx pluginapi.PlanContext) (pluginapi.PlanResult, error) {
	logger.Debugf("planValidate: kind=sshd\n")

	var details []string

	if ctx.Inspector.SSHIncludePresent() {
		details = append(details,
			logger.ColorGreen+"sshd_config: Include for /etc/ssh/sshd_config.d/*.conf is present"+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorRed+"sshd_config: Include for /etc/ssh/sshd_config.d/*.conf is missing (validate would fail)"+logger.ColorReset,
		)
	}

	testErr := ctx.Inspector.SSHConfigTest()
	if testErr == nil {
		details = append(details,
			logger.ColorGreen+"current sshd configuration: passes sshd -t"+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorRed+fmt.Sprintf("current sshd configuration: sshd -t reports errors (%v)", testErr)+logger.ColorReset,
		)
	}

	return pluginapi.PlanResult{
		Summary: "validate sshd: check Include hook and sshd -t on /etc/ssh/sshd_config",
		Details: details,
		Noop:    2,
	}, nil
}

func CaptureRollback(ctx pluginapi.RollbackContext, s profile.Step, deps RollbackDeps) (rollback.StepRecord, error) {
	record := rollback.StepRecord{
		ID:   s.ID,
		Type: "template",
	}
	if s.Template == nil {
		return record, fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
	}

	dest := strings.TrimSpace(s.Template.Dest)
	if err := rollbackutil.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=%s): %w", s.ID, s.Type, err)
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

func serviceForManagedPath(dest string) string {
	p := strings.TrimSpace(dest)
	switch {
	case strings.HasPrefix(p, "/etc/ssh/"):
		return "ssh"
	case strings.HasPrefix(p, "/etc/sysctl.d/"):
		return "systemd-sysctl"
	case strings.HasPrefix(p, "/etc/fail2ban/"):
		return "fail2ban"
	case strings.HasPrefix(p, "/etc/audit/"):
		return "auditd"
	case strings.HasPrefix(p, "/etc/systemd/journald.conf.d/"):
		return "systemd-journald"
	case strings.Contains(p, "nftables"):
		return "nftables"
	default:
		return ""
	}
}
