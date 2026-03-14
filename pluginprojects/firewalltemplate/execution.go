package main

import (
	"bytes"
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

const (
	firewallTemplateIncludeCheckCmd = `grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf 2>/dev/null`
	firewallTemplateMainConfigPath  = "/etc/nftables.conf"
	firewallTemplateIncludeLine     = `include "/etc/nftables.d/*.nft"`
)

type firewallTemplateStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type firewallTemplateCompareRuntime interface {
	firewallTemplateStatRuntime
	ReadRootFile(path string) (string, error)
}

func Apply(ctx pluginapi.ApplyContext, fw *Spec) error {
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
		if err := ctx.Host.RunRoot(fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := ensureNftablesInclude(ctx.Host); err != nil {
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

func Plan(ctx pluginapi.PlanContext, fw *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planFirewallTemplate: backend=%q allow_rules=%d template=%q -> %q\n", fw.Backend, len(fw.Allow), fw.TemplateSrc, fw.TemplateDest)
	if ctx.Host == nil {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall_template step: host context is required")
	}

	var details []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall_template step: unsupported backend %q (no-op)", fw.Backend)
		return pluginapi.PlanResult{
			Summary:         summary,
			Details:         []string{"only nftables backend is supported by executor"},
			Noop:            2,
			OperatorSummary: fmt.Sprintf("Unsupported firewall template backend %q requested", fw.Backend),
			Highlights:      []string{fmt.Sprintf("only the nftables backend is supported; got %q", fw.Backend)},
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
	details = append(details, logger.ColorYellow+"firewall_template diff is best-effort (template-driven)"+logger.ColorReset)

	summary := fmt.Sprintf(
		"firewall_template step (best-effort): backend=nftables template=%q -> %q allow_rules=%d",
		tmplPath, destPath, len(fw.Allow),
	)
	return pluginapi.PlanResult{
		Summary:         summary,
		Details:         details,
		Noop:            2,
		OperatorSummary: fmt.Sprintf("Render firewall template %q to %q with %d allow rule(s)", tmplPath, destPath, len(fw.Allow)),
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

func Capture(ctx pluginapi.CaptureContext, stepID string, spec *Spec) (pluginapi.StepRecord, error) {
	record := pluginapi.StepRecord{
		ID:   stepID,
		Type: "firewall_template",
	}
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

	record.RollbackMode = pluginapi.ModeDeterministic
	record.Objects = []pluginapi.ObjectRecord{
		{Kind: pluginapi.ObjectFile, File: &snap},
	}
	return record, nil
}

func ensureNftablesInclude(host pluginapi.Host) error {
	if host == nil {
		return fmt.Errorf("firewall_template step: host context is required")
	}
	if err := host.RunRoot(firewallTemplateIncludeCheckCmd); err == nil {
		return nil
	}

	appendCmd := `printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf`
	if err := host.RunRoot(appendCmd); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", firewallTemplateIncludeLine, firewallTemplateMainConfigPath, err)
	}

	if err := host.RunRoot(firewallTemplateIncludeCheckCmd); err != nil {
		return fmt.Errorf("verify %q in %s: %w", firewallTemplateIncludeLine, firewallTemplateMainConfigPath, err)
	}

	return nil
}
