package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"text/template"

	"github.com/karvashish/hardline/internals/plugins/firewall"
	"github.com/karvashish/hardline/internals/plugins/rollbackutil"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const DefaultManagedDestination = "/etc/nftables.d/99-hardline-firewall.nft"

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

type firewallTemplateStatRuntime interface {
	RunRoot(cmd string) error
	RunRootWithOutput(cmd string) (string, error)
}

type firewallTemplateCompareRuntime interface {
	firewallTemplateStatRuntime
	ReadRootFile(path string) (string, error)
}

type firewallTemplateApplyRuntime struct {
	client *ssh.Client
	deps   ApplyDeps
}

func (r firewallTemplateApplyRuntime) RunRoot(cmd string) error {
	return r.deps.RunRoot(r.client, cmd)
}

func (r firewallTemplateApplyRuntime) RunRootWithOutput(cmd string) (string, error) {
	return r.deps.RunRootWithOutput(r.client, cmd)
}

func (r firewallTemplateApplyRuntime) ReadRootFile(path string) (string, error) {
	return r.deps.ReadRootFile(r.client, path)
}

func Apply(ctx pluginapi.ApplyContext, fw *Spec, deps ApplyDeps) error {
	logger.Debugf("handleFirewallTemplate: backend=%q allow_rules=%d\n", fw.Backend, len(fw.Allow))

	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}
	if ctx.Profile == nil {
		return fmt.Errorf("firewall_template step: profile context is required")
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
		if err := deps.RunRoot(ctx.Client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := firewall.EnsureNftablesInclude(ctx.Client, deps.RunRoot); err != nil {
		return err
	}

	if canCompareFirewallTemplateDestination(deps) {
		matches, err := firewallTemplateDestinationMatches(firewallTemplateApplyRuntime{client: ctx.Client, deps: deps}, destPath, rendered, os.FileMode(0644))
		if err != nil {
			return fmt.Errorf("compare destination %s: %w", destPath, err)
		}
		if matches {
			logger.Debugf("handleFirewallTemplate: destination %q already matches, skipping write\n", destPath)
			return nil
		}
	}

	sftpClient, err := deps.NewSFTPClient(ctx.Client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := deps.WriteRootFile(ctx.Client, sftpClient, destPath, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", destPath, err)
	}
	return nil
}

func canCompareFirewallTemplateDestination(deps ApplyDeps) bool {
	return deps.RunRoot != nil && deps.RunRootWithOutput != nil && deps.ReadRootFile != nil
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

	var details []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall_template step: unsupported backend %q (no-op)", fw.Backend)
		return pluginapi.PlanResult{Summary: summary, Details: []string{"only nftables backend is supported by executor"}, Noop: 2}, nil
	}

	tmplPath := strings.TrimSpace(fw.TemplateSrc)
	if tmplPath == "" {
		tmplPath = "templates/nftables_base.tmpl"
	}
	destPath := strings.TrimSpace(fw.TemplateDest)
	if destPath == "" {
		destPath = ManagedDestination(fw)
	}

	info, err := ctx.Runtime.Stat(destPath)
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
	return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
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

func CaptureRollback(ctx pluginapi.RollbackContext, stepID string, spec *Spec, deps RollbackDeps) (rollback.StepRecord, error) {
	record := rollback.StepRecord{
		ID:   stepID,
		Type: "firewall_template",
	}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=firewall_template): firewall_template spec missing", stepID)
	}

	dest := ManagedDestination(spec)
	if err := rollbackutil.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=firewall_template): %w", stepID, err)
	}

	snap, err := rollbackutil.SnapshotRemoteFile(ctx.Client, dest, rollbackutil.Deps{
		RunRoot:           deps.RunRoot,
		RunRootWithOutput: deps.RunRootWithOutput,
		ReadRootFile:      deps.ReadRootFile,
	})
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", dest, err)
	}

	record.RollbackMode = rollback.ModeDeterministic
	record.Objects = []rollback.ObjectRecord{
		{Kind: rollback.ObjectFile, File: &snap},
	}
	return record, nil
}
