package ssh

import (
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const candidateSuffix = ".hardline-candidate"

func candidatePath(dest string) string {
	return dest + candidateSuffix
}

func sshdBinary(host pluginapi.Host) (string, error) {
	out, err := host.RunRootWithOutput("command -v sshd || command -v /usr/sbin/sshd || true")
	if err != nil {
		return "", fmt.Errorf("locate sshd: %w", err)
	}
	bin := strings.TrimSpace(out)
	if bin == "" {
		return "", fmt.Errorf("sshd is not installed on this host, so its configuration cannot be validated or verified")
	}
	if strings.ContainsAny(bin, " \t\n") {
		return "", fmt.Errorf("locate sshd: unexpected output %q", out)
	}
	return bin, nil
}

func checkFile(host pluginapi.Host, bin, file string) error {
	out, err := host.RunRootWithOutput(pluginapi.ShellArg(bin) + " -t -f " + pluginapi.ShellArg(file) + " 2>&1")
	if err != nil {
		return fmt.Errorf("sshd rejected the rendered configuration: %s", firstLines(out, 5))
	}
	return nil
}

func checkMainConfig(host pluginapi.Host, bin string) error {
	out, err := host.RunRootWithOutput(pluginapi.ShellArg(bin) + " -t 2>&1")
	if err != nil {
		return fmt.Errorf("the host sshd configuration does not parse with this drop-in in place: %s", firstLines(out, 5))
	}
	return nil
}

func effectiveConfig(host pluginapi.Host, bin string, mc *MatchContext) (map[string][]string, error) {
	cmd := pluginapi.ShellArg(bin) + " -T"
	label := "sshd -T"
	if mc != nil {
		spec := fmt.Sprintf("user=%s,host=%s,addr=%s", mc.User, mc.Host, mc.Address)
		cmd += " -C " + pluginapi.ShellArg(spec)
		label = "sshd -T -C " + spec
	}

	out, err := host.RunRootWithOutput(cmd + " 2>&1")
	if err != nil {
		return nil, fmt.Errorf("read the effective sshd configuration (%s): %s", label, firstLines(out, 5))
	}
	effective := ParseEffective(out)
	if len(effective) == 0 {
		return nil, fmt.Errorf("%s reported no configuration", label)
	}
	return effective, nil
}

func connectingUser(host pluginapi.Host) (string, error) {
	out, err := host.RunRootWithOutput(`printf '%s' "${SUDO_USER:-root}"`)
	if err != nil {
		return "", fmt.Errorf("determine the connecting user: %w", err)
	}
	user := strings.TrimSpace(out)
	if user == "" {
		return "", fmt.Errorf("could not determine the connecting user; refusing to change sshd policy that may lock this host out")
	}
	return user, nil
}

func userGroups(host pluginapi.Host, user string) ([]string, error) {
	out, err := host.RunRootWithOutput("id -nG " + pluginapi.ShellArg(user) + " 2>/dev/null || true")
	if err != nil {
		return nil, fmt.Errorf("read the groups of %q: %w", user, err)
	}
	return strings.Fields(out), nil
}

func assertManagementAccess(effective map[string][]string, user string, groups []string) error {
	if user == "root" {
		switch value := firstValue(effective, "permitrootlogin"); strings.ToLower(value) {
		case "no", "forced-commands-only":
			return fmt.Errorf("refusing to activate: this run is connected as root and the resulting policy sets PermitRootLogin %s, which would lock hardline out of this host", value)
		}
	}

	if value := firstValue(effective, "pubkeyauthentication"); value != "" && !strings.EqualFold(value, "yes") {
		return fmt.Errorf("refusing to activate: the resulting policy sets PubkeyAuthentication %s, and this run authenticates by key", value)
	}

	if err := assertListed(effective, "denyusers", []string{user}, false); err != nil {
		return err
	}
	if err := assertListed(effective, "allowusers", []string{user}, true); err != nil {
		return err
	}
	if err := assertListed(effective, "denygroups", groups, false); err != nil {
		return err
	}
	return assertListed(effective, "allowgroups", groups, true)
}

func assertListed(effective map[string][]string, key string, names []string, mustMatch bool) error {
	patterns := strings.Fields(firstValue(effective, key))
	if len(patterns) == 0 {
		return nil
	}

	matched := false
	for _, pattern := range patterns {
		if strings.HasPrefix(pattern, "!") || strings.Contains(pattern, "@") {
			return fmt.Errorf("refusing to activate: the resulting policy sets %s %s, whose pattern %q this check cannot evaluate; hardline will not guess whether it keeps its own access",
				key, strings.Join(patterns, " "), pattern)
		}
		for _, name := range names {
			if ok, err := path.Match(pattern, name); err == nil && ok {
				matched = true
			}
		}
	}

	if matched == mustMatch {
		return nil
	}
	if mustMatch {
		return fmt.Errorf("refusing to activate: the resulting policy sets %s %s, which does not cover this run's identity (%s), so hardline would lose access to this host",
			key, strings.Join(patterns, " "), strings.Join(names, ", "))
	}
	return fmt.Errorf("refusing to activate: the resulting policy sets %s %s, which covers this run's identity (%s), so hardline would lose access to this host",
		key, strings.Join(patterns, " "), strings.Join(names, ", "))
}

func firstValue(effective map[string][]string, key string) string {
	values := effective[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func verifyEffective(host pluginapi.Host, bin string, want []Setting, contexts []MatchContext) error {
	global, err := effectiveConfig(host, bin, nil)
	if err != nil {
		return err
	}
	if drift := DivergentSettings(global, want); len(drift) > 0 {
		return fmt.Errorf("the running sshd policy is not what the profile declares:\n  %s", strings.Join(drift, "\n  "))
	}

	for i := range contexts {
		mc := contexts[i]
		matched, err := effectiveConfig(host, bin, &mc)
		if err != nil {
			return err
		}
		if drift := DivergentSettings(matched, want); len(drift) > 0 {
			return fmt.Errorf("the sshd policy for %s@%s from %s is not what the profile declares, so a Match block overrides it:\n  %s",
				mc.User, mc.Host, mc.Address, strings.Join(drift, "\n  "))
		}
	}
	return nil
}

func reload(host pluginapi.Host, service string) error {
	if err := host.RunRoot("systemctl reload " + pluginapi.ShellArg(service)); err != nil {
		return fmt.Errorf("reload %s: %w", service, err)
	}
	return nil
}

func aligned(current pluginapi.FileSnapshot, rendered []byte, mode os.FileMode) bool {
	return current.Existed &&
		current.ContentB64 == base64.StdEncoding.EncodeToString(rendered) &&
		current.Mode == fmt.Sprintf("%o", mode.Perm())
}

func firstLines(out string, n int) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.TrimSpace(strings.Join(lines, "; "))
}

func install(host pluginapi.Host, bin, dest string, rendered []byte, mode os.FileMode) error {
	staged := candidatePath(dest)
	if err := host.WriteRootFile(staged, rendered, mode); err != nil {
		return fmt.Errorf("stage %s: %w", staged, err)
	}
	defer func() {
		if err := host.RunRoot("rm -f " + pluginapi.ShellArg(staged)); err != nil {
			logger.Debugf("ssh: could not remove staged candidate %s: %v\n", staged, err)
		}
	}()

	if err := checkFile(host, bin, staged); err != nil {
		return err
	}
	if err := host.RunRoot("mv -f " + pluginapi.ShellArg(staged) + " " + pluginapi.ShellArg(dest)); err != nil {
		return fmt.Errorf("install %s: %w", dest, err)
	}
	return nil
}

func Apply(ctx pluginapi.Context, spec *Spec) error {
	logger.Debugf("handleSSH: path=%q service=%q\n", spec.Path, spec.Service)
	if ctx.Host == nil {
		return fmt.Errorf("ssh step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Path); err != nil {
		return fmt.Errorf("ssh apply: %w", err)
	}

	settings, err := ParseSettings(spec.Settings)
	if err != nil {
		return fmt.Errorf("ssh step: %w", err)
	}
	mode, err := pluginapi.ParseFileMode(spec.Mode)
	if err != nil {
		return fmt.Errorf("ssh step: %w", err)
	}
	rendered := Render(settings)

	bin, err := sshdBinary(ctx.Host)
	if err != nil {
		return err
	}
	user, err := connectingUser(ctx.Host)
	if err != nil {
		return err
	}
	groups, err := userGroups(ctx.Host, user)
	if err != nil {
		return err
	}

	before, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Path)
	if err != nil {
		return fmt.Errorf("read %s: %w", spec.Path, err)
	}

	fileMatches := aligned(before, rendered, mode)
	if fileMatches {
		if err := verifyEffective(ctx.Host, bin, settings, spec.VerifyContexts); err == nil {
			logger.Debugf("handleSSH: %s already active, skipping reload\n", spec.Path)
			return nil
		}
	} else if err := install(ctx.Host, bin, spec.Path, rendered, mode); err != nil {
		return err
	}

	reloaded := false
	activate := func() error {
		if err := checkMainConfig(ctx.Host, bin); err != nil {
			return err
		}
		prospective, err := effectiveConfig(ctx.Host, bin, nil)
		if err != nil {
			return err
		}
		if err := assertManagementAccess(prospective, user, groups); err != nil {
			return err
		}
		reloaded = true
		if err := reload(ctx.Host, spec.Service); err != nil {
			return err
		}
		return verifyEffective(ctx.Host, bin, settings, spec.VerifyContexts)
	}

	if err := activate(); err != nil {
		if restoreErr := restorePrevious(ctx.Host, bin, before, spec.Service, reloaded); restoreErr != nil {
			return fmt.Errorf("%w (and restoring the previous %s failed: %v)", err, spec.Path, restoreErr)
		}
		return err
	}
	return nil
}

func restorePrevious(host pluginapi.Host, bin string, before pluginapi.FileSnapshot, service string, reloaded bool) error {
	if err := pluginapi.RestoreFileSnapshot(host, before); err != nil {
		return err
	}
	if !reloaded {
		return nil
	}
	if err := checkMainConfig(host, bin); err != nil {
		return fmt.Errorf("after restoring %s: %w", before.Path, err)
	}
	return reload(host, service)
}

func Plan(ctx pluginapi.Context, spec *Spec) (pluginapi.PlanResult, error) {
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("ssh step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Path); err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("ssh plan: %w", err)
	}

	settings, err := ParseSettings(spec.Settings)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("ssh step: %w", err)
	}
	mode, err := pluginapi.ParseFileMode(spec.Mode)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("ssh step: %w", err)
	}
	rendered := Render(settings)

	bin, err := sshdBinary(ctx.Host)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	current, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Path)
	if err != nil {
		return pluginapi.PlanResult{}, fmt.Errorf("read %s: %w", spec.Path, err)
	}
	effective, err := effectiveConfig(ctx.Host, bin, nil)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}

	fileMatches := aligned(current, rendered, mode)
	drift := DivergentSettings(effective, settings)

	var details, diffs, highlights []string
	if fileMatches {
		details = append(details, fmt.Sprintf("%s%s: already matches%s", logger.ColorBlue, spec.Path, logger.ColorReset))
	} else {
		verb := "rewritten"
		if !current.Existed {
			verb = "created"
		}
		details = append(details, fmt.Sprintf("%s%s: will be %s with %d keyword(s)%s",
			logger.ColorGreen, spec.Path, verb, len(settings), logger.ColorReset))
		diffs = append(diffs, fmt.Sprintf("file %q: %s -> rendered sshd policy", spec.Path, verb))
	}

	if len(drift) == 0 {
		details = append(details, fmt.Sprintf("%srunning sshd policy already carries all %d keyword(s)%s",
			logger.ColorBlue, len(settings), logger.ColorReset))
	} else {
		details = append(details, fmt.Sprintf("%srunning sshd policy diverges on %d keyword(s)%s",
			logger.ColorYellow, len(drift), logger.ColorReset))
		for _, item := range drift {
			details = append(details, "  "+item)
		}
		diffs = append(diffs, fmt.Sprintf("sshd policy: reload %s to take %d keyword(s)", spec.Service, len(drift)))
	}

	user, err := connectingUser(ctx.Host)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	groups, err := userGroups(ctx.Host, user)
	if err != nil {
		return pluginapi.PlanResult{}, err
	}
	if err := assertManagementAccess(effective, user, groups); err != nil {
		highlights = append(highlights, err.Error())
		details = append(details, logger.ColorRed+err.Error()+logger.ColorReset)
	}

	willChange := !fileMatches || len(drift) > 0
	summary := "ssh step: drop-in and running sshd policy already aligned"
	operator := "sshd policy already matches the profile"
	if willChange {
		summary = fmt.Sprintf("ssh step: write %s and reload %s", spec.Path, spec.Service)
		operator = fmt.Sprintf("Write the sshd policy to %s and reload %s so it takes effect", spec.Path, spec.Service)
	}

	return pluginapi.PlanResult{
		Summary:          summary,
		Details:          details,
		Diff:             diffs,
		WillChange:       willChange,
		OperatorSummary:  operator,
		Highlights:       highlights,
		RollbackFidelity: pluginapi.ModeDeterministic,
	}, nil
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if ctx.Host == nil {
		return record, fmt.Errorf("ssh step: host context is required")
	}
	if err := pluginapi.EnforceManagedPath(spec.Path); err != nil {
		return record, fmt.Errorf("step %q (type=ssh): %w", stepID, err)
	}

	snap, err := pluginapi.SnapshotRemoteFile(ctx.Host, spec.Path)
	if err != nil {
		return record, fmt.Errorf("capture sshd policy for %q: %w", spec.Path, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{{
		Kind:    pluginapi.ObjectFile,
		File:    &snap,
		Message: spec.Service,
	}}
	return record, nil
}

func ServiceUnit(record pluginapi.ObjectRecord) (string, error) {
	switch unit := strings.TrimSpace(record.Message); unit {
	case "ssh", "sshd":
		return unit, nil
	case "":
		return "", fmt.Errorf("ssh rollback: the journal records no sshd unit name for %s", record.File.Path)
	default:
		return "", fmt.Errorf("ssh rollback: the journal records an unsupported sshd unit name %q", unit)
	}
}

func Restore(host pluginapi.Host, snap pluginapi.FileSnapshot, service string) error {
	if host == nil {
		return fmt.Errorf("ssh rollback: host is required")
	}
	if err := pluginapi.RestoreFileSnapshot(host, snap); err != nil {
		return err
	}

	bin, err := sshdBinary(host)
	if err != nil {
		return err
	}
	if err := checkMainConfig(host, bin); err != nil {
		return fmt.Errorf("after restoring %s: %w", snap.Path, err)
	}
	return reload(host, service)
}
