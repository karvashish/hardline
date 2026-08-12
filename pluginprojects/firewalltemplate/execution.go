package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const DefaultManagedDestination = "/etc/nftables.d/99-hardline-firewall.nft"

// The nftables service reads a different main config per distribution family,
// so the profile states which one this host uses.
const (
	MainConfigDebian = "/etc/nftables.conf"
	MainConfigRHEL   = "/etc/sysconfig/nftables.conf"
)

func validMainConfig(p string) bool {
	switch strings.TrimSpace(p) {
	case MainConfigDebian, MainConfigRHEL:
		return true
	default:
		return false
	}
}

func includeLine(dest string) string {
	return fmt.Sprintf(`include "%s/*.nft"`, path.Dir(dest))
}

func includeCheckCmd(mainConfig, dest string) string {
	glob := strings.ReplaceAll(path.Dir(dest)+"/*.nft", ".", `\.`)
	glob = strings.ReplaceAll(glob, "*", `\*`)
	return fmt.Sprintf(`grep -E -q 'include[[:space:]]+"?%s"?' %s 2>/dev/null`, glob, pluginapi.ShellArg(mainConfig))
}

type firewallTemplateStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type firewallTemplateCompareRuntime interface {
	firewallTemplateStatRuntime
	ReadRootFile(path string) (string, error)
}

func Apply(ctx pluginapi.Context, fw *Spec) error {
	logger.Debugf("handleFirewallTemplate: backend=%q allow_rules=%d\n", fw.Backend, len(fw.Allow))

	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}
	if ctx.Profile == nil {
		return fmt.Errorf("firewall_template step: profile context is required")
	}
	if ctx.Host == nil {
		return fmt.Errorf("firewall_template step: host context is required")
	}

	tmplPath := strings.TrimSpace(fw.TemplateSrc)
	if tmplPath == "" {
		tmplPath = "templates/nftables_base.tmpl"
	}

	tmplData, err := ctx.Profile.LoadTemplate(tmplPath)
	if err != nil {
		return fmt.Errorf("load nftables template %q: %w", tmplPath, err)
	}

	funcMap := template.FuncMap{
		"allow_rules": func() string {
			var b strings.Builder
			if len(fw.Allow) == 0 {
				b.WriteString("# hardline: no explicit allow rules in profile\n")
				return b.String()
			}
			b.WriteString("# hardline: allow rules from profile\n")
			for _, rule := range fw.Allow {
				proto := strings.ToLower(strings.TrimSpace(rule.Proto))
				if proto == "" {
					proto = "tcp"
				}
				fmt.Fprintf(&b, "    %s dport %d accept\n", proto, rule.Port)
			}
			return b.String()
		},
	}

	t, err := template.New("nftables").Funcs(funcMap).Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("parse nftables template %q: %w", tmplPath, err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, nil); err != nil {
		return fmt.Errorf("execute nftables template %q: %w", tmplPath, err)
	}
	rendered := buf.String()

	destPath := ManagedDestination(fw)
	dir := path.Dir(destPath)
	if dir != "" && dir != "." {
		if err := ctx.Host.RunRoot("mkdir -p " + pluginapi.ShellArg(dir)); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := ensureNftablesInclude(ctx.Host, fw.MainConfig, destPath); err != nil {
		return err
	}

	matches, err := firewallTemplateDestinationMatches(ctx.Host, destPath, rendered, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("compare destination %s: %w", destPath, err)
	}
	if matches {
		logger.Debugf("handleFirewallTemplate: destination %q already matches, skipping write\n", destPath)
		return nil
	}

	if err := ctx.Host.WriteRootFile(destPath, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("write root file %s: %w", destPath, err)
	}
	return nil
}

func firewallTemplateDestinationMatches(rt firewallTemplateCompareRuntime, dest, rendered string, mode os.FileMode) (bool, error) {
	size, currentMode, err := statFirewallTemplateDestination(rt, dest)
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
	return current == rendered, nil
}

func statFirewallTemplateDestination(rt firewallTemplateStatRuntime, dest string) (int64, os.FileMode, error) {
	if rt == nil {
		return 0, 0, fmt.Errorf("runtime is required")
	}
	if err := rt.RunRoot(fmt.Sprintf("test -e %s", pluginapi.ShellArg(dest))); err != nil {
		return -1, 0, nil
	}

	out, err := rt.RunRootWithOutput(fmt.Sprintf("stat -c '%%a %%s' -- %s", pluginapi.ShellArg(dest)))
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

func Plan(ctx pluginapi.Context, fw *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planFirewallTemplate: backend=%q allow_rules=%d template=%q -> %q\n", fw.Backend, len(fw.Allow), fw.TemplateSrc, fw.TemplateDest)
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall_template step: host context is required")
	}

	var details []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall_template step: unsupported backend %q (no-op)", fw.Backend)
		return pluginapi.PlanResult{
			Summary:          summary,
			Details:          []string{"only nftables backend is supported by executor"},
			WillChange:       true,
			OperatorSummary:  fmt.Sprintf("Unsupported firewall template backend %q requested", fw.Backend),
			Highlights:       []string{fmt.Sprintf("only the nftables backend is supported; got %q", fw.Backend)},
			RollbackFidelity: pluginapi.ModeDeterministic,
		}, nil
	}

	tmplPath := strings.TrimSpace(fw.TemplateSrc)
	if tmplPath == "" {
		tmplPath = "templates/nftables_base.tmpl"
	}
	destPath := strings.TrimSpace(fw.TemplateDest)
	if destPath == "" {
		destPath = ManagedDestination(fw)
	}

	info, err := ctx.Host.Stat(destPath)
	if err != nil {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("destination %q: does not exist (file will be created)", destPath)+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("destination %q: exists (size=%d mode=%#o)", destPath, info.Size(), info.Mode().Perm())+logger.ColorReset,
		)
	}
	details = append(details, logger.ColorGreen+fmt.Sprintf("template source: %q", tmplPath)+logger.ColorReset)
	details = append(details, logger.ColorDim+"note: diff shows expected file content; live nftables ruleset may differ"+logger.ColorReset)

	summary := fmt.Sprintf(
		"firewall_template step: backend=nftables template=%q -> %q allow_rules=%d",
		tmplPath, destPath, len(fw.Allow),
	)
	return pluginapi.PlanResult{
		Summary:          summary,
		Details:          details,
		WillChange:       true,
		OperatorSummary:  fmt.Sprintf("Render firewall template %q to %q with %d allow rule(s)", tmplPath, destPath, len(fw.Allow)),
		RollbackFidelity: pluginapi.ModeDeterministic,
	}, nil
}

func ManagedDestination(fw *Spec) string {
	if fw == nil {
		return DefaultManagedDestination
	}
	dest := strings.TrimSpace(fw.TemplateDest)
	if dest == "" {
		return DefaultManagedDestination
	}
	return dest
}

func Capture(ctx pluginapi.Context, stepID string, spec *Spec) (pluginapi.CaptureResult, error) {
	record := pluginapi.CaptureResult{}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=firewall_template): firewall_template spec missing", stepID)
	}
	if ctx.Host == nil {
		return record, fmt.Errorf("firewall_template step: host context is required")
	}

	dest := ManagedDestination(spec)
	if err := pluginapi.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=firewall_template): %w", stepID, err)
	}

	snap, err := pluginapi.SnapshotRemoteFile(ctx.Host, dest)
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", dest, err)
	}

	// Apply also appends the include line to the main config, so that file has
	// to be journalled too. Without it rollback leaves the include behind, and
	// an include-only apply produces equal before/after captures, which lets an
	// on_change service dependency skip the restart the include requires.
	mainConfig := strings.TrimSpace(spec.MainConfig)
	if !validMainConfig(mainConfig) {
		return record, fmt.Errorf("step %q (type=firewall_template): unsupported main_config %q", stepID, spec.MainConfig)
	}
	mainSnap, err := pluginapi.SnapshotRemoteFile(ctx.Host, mainConfig)
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", mainConfig, err)
	}

	record.RollbackMode = pluginapi.ModeDeterministic
	// Rollback walks Before in reverse, so listing the main config first
	// restores the managed file before the include that points at its directory.
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectFile, File: &mainSnap},
		{Kind: pluginapi.ObjectFile, File: &snap},
	}
	return record, nil
}

// restoreMainConfig reverts the nftables main config to its pre-apply bytes,
// which is what removes the include line apply appended. It skips
// EnforceManagedPath, whose 99-hardline naming rule this file cannot satisfy,
// and checks the two-entry whitelist instead: a tampered journal must not be
// able to name any other path here.
func restoreMainConfig(host pluginapi.Host, snap pluginapi.FileSnapshot) error {
	if host == nil {
		return fmt.Errorf("firewall_template rollback: host is required")
	}
	if !validMainConfig(snap.Path) {
		return fmt.Errorf("firewall_template rollback: unexpected main config path %q", snap.Path)
	}

	if !snap.Existed {
		return host.RunRoot("rm -f " + pluginapi.ShellArg(snap.Path))
	}

	mode := os.FileMode(0o600)
	if trimmed := strings.TrimSpace(snap.Mode); trimmed != "" {
		if parsed, err := strconv.ParseUint(trimmed, 8, 32); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	content, err := base64.StdEncoding.DecodeString(snap.ContentB64)
	if err != nil {
		return fmt.Errorf("decode snapshot content for %q: %w", snap.Path, err)
	}
	if err := host.WriteRootFile(snap.Path, content, mode); err != nil {
		return fmt.Errorf("restore file %q: %w", snap.Path, err)
	}
	return nil
}

func ensureNftablesInclude(host pluginapi.Host, mainConfig, dest string) error {
	if host == nil {
		return fmt.Errorf("firewall_template step: host context is required")
	}
	check := includeCheckCmd(mainConfig, dest)
	if err := host.RunRoot(check); err == nil {
		return nil
	}

	include := includeLine(dest)
	appendCmd := fmt.Sprintf("printf '\\n%%s\\n' %s >> %s", pluginapi.ShellArg(include), pluginapi.ShellArg(mainConfig))
	if err := host.RunRoot(appendCmd); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", include, mainConfig, err)
	}

	if err := host.RunRoot(check); err != nil {
		return fmt.Errorf("verify %q in %s: %w", include, mainConfig, err)
	}

	return nil
}
