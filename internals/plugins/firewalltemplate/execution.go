package firewalltemplate

import (
	"bytes"
	"fmt"
	"os"
	"path"
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
	if deps.MarkServiceDirty != nil {
		deps.MarkServiceDirty("nftables")
	}
	return nil
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

	info, err := ctx.Inspector.Stat(destPath)
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
