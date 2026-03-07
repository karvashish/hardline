package apply

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	runRootCmd           = remote.RunRoot
	runRootCmdWithOutput = remote.RunRootWithOutput
	readRootFile         = remote.ReadRootFile
	newSFTPClient        = func(client *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(client) }
	writeRootFile        = remote.WriteRootFile
	serviceDirty         = make(map[string]bool)
)

const (
	defaultManagedFirewallTemplateDest = "/etc/nftables.d/99-hardline-firewall.nft"
	nftablesMainConfigPath             = "/etc/nftables.conf"
	nftablesIncludeLine                = `include "/etc/nftables.d/*.nft"`
	firewallIncludeCheckCmd            = `grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf`
)

func resetApplyStepState() {
	serviceDirty = make(map[string]bool)
}

func normalizeServiceUnit(unit string) string {
	name := strings.TrimSpace(unit)
	if name == "sshd" {
		return "ssh"
	}
	return name
}

func markServiceDirty(unit string) {
	u := normalizeServiceUnit(unit)
	if u == "" {
		return
	}
	serviceDirty[u] = true
}

func clearServiceDirty(unit string) {
	u := normalizeServiceUnit(unit)
	delete(serviceDirty, u)
}

func isServiceDirty(unit string) bool {
	u := normalizeServiceUnit(unit)
	return serviceDirty[u]
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

func managedFileUpToDate(client *ssh.Client, dest string, data []byte, mode os.FileMode) bool {
	wantMode := fmt.Sprintf("%03o", mode.Perm())
	wantB64 := base64.StdEncoding.EncodeToString(data)
	checkCmd := fmt.Sprintf(
		"test -e %q && [ \"$(stat -c %%a %q)\" = %q ] && printf '%%s' %q | base64 -d | cmp -s - %q",
		dest, dest, wantMode, wantB64, dest,
	)
	return runRootCmd(client, checkCmd) == nil
}

func serviceIsEnabled(client *ssh.Client, unit string) bool {
	cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1", unit)
	return runRootCmd(client, cmd) == nil
}

func serviceIsActive(client *ssh.Client, unit string) bool {
	cmd := fmt.Sprintf("systemctl is-active %s >/dev/null 2>&1", unit)
	return runRootCmd(client, cmd) == nil
}

func handleStep(client *ssh.Client, p *profile.Profile, s profile.Step) error {
	stepType := strings.ToLower(strings.TrimSpace(s.Type))

	switch stepType {
	case "packages":
		if s.Packages == nil {
			return fmt.Errorf("step %q (type=%s): packages spec missing", s.ID, s.Type)
		}
		return handlePackages(client, s.Packages)
	case "template":
		if s.Template == nil {
			return fmt.Errorf("step %q (type=%s): template spec missing", s.ID, s.Type)
		}
		return handleTemplate(client, p, s.Template)
	case "service":
		if s.Service == nil {
			return fmt.Errorf("step %q (type=%s): service spec missing", s.ID, s.Type)
		}
		return handleService(client, s.Service)
	case "firewall":
		if s.Firewall == nil {
			return fmt.Errorf("step %q (type=%s): firewall spec missing", s.ID, s.Type)
		}
		return handleFirewall(client, s.Firewall)
	case "firewall_template":
		if s.FirewallTemplate == nil {
			return fmt.Errorf("step %q (type=%s): firewall_template spec missing", s.ID, s.Type)
		}
		return handleFirewallTemplate(client, p, s.FirewallTemplate)
	case "validate":
		if strings.TrimSpace(s.Validate) == "" {
			return fmt.Errorf("step %q (type=%s): validate spec missing", s.ID, s.Type)
		}
		return handleValidate(client, s.Validate)
	default:
		logger.Warnf("warning: empty or unknown step type %q (id=%q)\n", s.Type, s.ID)
		return nil
	}
}

func handlePackages(client *ssh.Client, pk *profile.PackageSpec) error {
	logger.Debugf(
		"handlePackages: update=%v upgrade=%v install=%v purge=%v autoremove=%v\n",
		pk.Update, pk.Upgrade, pk.Install, pk.Purge, pk.Autoremove,
	)

	if pk.Update {
		if err := runRootCmd(client, "apt-get update -y"); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}
	}

	if pk.Upgrade {
		if err := runRootCmd(client, "apt-get upgrade -y"); err != nil {
			return fmt.Errorf("apt-get upgrade failed: %w", err)
		}
	}

	if len(pk.Install) > 0 {
		cmd := "apt-get install -y " + strings.Join(pk.Install, " ")
		if err := runRootCmd(client, cmd); err != nil {
			return fmt.Errorf("apt-get install failed (%s): %w", strings.Join(pk.Install, ","), err)
		}
	}

	if len(pk.Purge) > 0 {
		cmd := "apt-get purge -y " + strings.Join(pk.Purge, " ")
		if err := runRootCmd(client, cmd); err != nil {
			return fmt.Errorf("apt-get purge failed (%s): %w", strings.Join(pk.Purge, ","), err)
		}
	}

	if pk.Autoremove {
		if err := runRootCmd(client, "apt-get autoremove -y"); err != nil {
			return fmt.Errorf("apt-get autoremove failed: %w", err)
		}
	}

	return nil
}

func handleTemplate(client *ssh.Client, p *profile.Profile, t *profile.TemplateSpec) error {
	logger.Debugf("handleTemplate: src=%q dest=%q mode=%q\n", t.Src, t.Dest, t.Mode)

	data, err := p.LoadTemplate(t.Src)
	if err != nil {
		return fmt.Errorf("load template %q: %w", t.Src, err)
	}

	sftpClient, err := newSFTPClient(client)
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

	if managedFileUpToDate(client, t.Dest, data, mode) {
		logger.Debugf("handleTemplate: destination %q already up to date, skipping write\n", t.Dest)
		return nil
	}

	dir := path.Dir(t.Dest)
	if dir != "" && dir != "." {
		if err := runRootCmd(client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	if err := writeRootFile(client, sftpClient, t.Dest, data, mode); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", t.Dest, err)
	}
	markServiceDirty(serviceForManagedPath(t.Dest))

	return nil
}

func handleService(client *ssh.Client, s *profile.ServiceSpec) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}

	unit := s.Name

	if unit == "sshd" {
		unit = "ssh"
	}
	unit = normalizeServiceUnit(unit)
	logger.Debugf("handleService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, s.Enabled, s.State)

	if s.Enabled != nil {
		enabledNow := serviceIsEnabled(client, unit)
		if *s.Enabled != enabledNow {
			var cmd string
			if *s.Enabled {
				cmd = fmt.Sprintf("systemctl enable %s", unit)
			} else {
				cmd = fmt.Sprintf("systemctl disable %s", unit)
			}
			if err := runRootCmd(client, cmd); err != nil {
				return fmt.Errorf("systemctl enable/disable %s: %w", unit, err)
			}
		} else {
			logger.Debugf("handleService: enablement already matches for %s, skipping toggle\n", unit)
		}
	}

	state := strings.ToLower(strings.TrimSpace(s.State))
	if state == "" {
		return nil
	}

	var cmd string
	switch state {
	case "started", "start":
		if serviceIsActive(client, unit) {
			logger.Debugf("handleService: %s already active, skipping start\n", unit)
			clearServiceDirty(unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl start %s", unit)
	case "stopped", "stop":
		if !serviceIsActive(client, unit) {
			logger.Debugf("handleService: %s already inactive, skipping stop\n", unit)
			clearServiceDirty(unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl stop %s", unit)
	case "restarted", "restart":
		if !isServiceDirty(unit) && serviceIsActive(client, unit) {
			logger.Debugf("handleService: %s clean and active, skipping restart\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl restart %s", unit)
	case "reloaded", "reload", "reload-or-restart":
		if !isServiceDirty(unit) && serviceIsActive(client, unit) {
			logger.Debugf("handleService: %s clean and active, skipping reload-or-restart\n", unit)
			return nil
		}
		cmd = fmt.Sprintf("systemctl reload-or-restart %s", unit)
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := runRootCmd(client, cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}
	clearServiceDirty(unit)

	return nil
}

func handleFirewallTemplate(client *ssh.Client, p *profile.Profile, fw *profile.FirewallTemplateSpec) error {
	logger.Debugf("handleFirewallTemplate: backend=%q allow_rules=%d\n", fw.Backend, len(fw.Allow))

	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}

	tmplPath := strings.TrimSpace(fw.TemplateSrc)
	if tmplPath == "" {
		tmplPath = "templates/nftables_base.tmpl"
	}

	tmplData, err := p.LoadTemplate(tmplPath)
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

	// allow firewall spec to override destination; fallback keeps old behavior
	destPath := managedFirewallTemplateDestination(fw)

	dir := path.Dir(destPath)
	if dir != "" && dir != "." {
		if err := runRootCmd(client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	if err := ensureNftablesInclude(client); err != nil {
		return err
	}

	sftpClient, err := newSFTPClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	if err := writeRootFile(client, sftpClient, destPath, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", destPath, err)
	}
	markServiceDirty("nftables")
	return nil
}

func managedFirewallTemplateDestination(fw *profile.FirewallTemplateSpec) string {
	if fw == nil {
		return defaultManagedFirewallTemplateDest
	}
	dest := strings.TrimSpace(fw.TemplateDest)
	if dest == "" {
		return defaultManagedFirewallTemplateDest
	}
	return dest
}

func ensureNftablesInclude(client *ssh.Client) error {
	if err := runRootCmd(client, firewallIncludeCheckCmd); err == nil {
		return nil
	}

	appendCmd := "printf '\\ninclude \"/etc/nftables.d/*.nft\"\\n' >> /etc/nftables.conf"
	if err := runRootCmd(client, appendCmd); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", nftablesIncludeLine, nftablesMainConfigPath, err)
	}

	if err := runRootCmd(client, firewallIncludeCheckCmd); err != nil {
		return fmt.Errorf("verify %q in %s: %w", nftablesIncludeLine, nftablesMainConfigPath, err)
	}

	return nil
}

func handleValidate(client *ssh.Client, kind string) error {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sshd":
		logger.Debugf("handleValidate: kind=sshd\n")

		checkIncludeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config`
		if err := runRootCmd(client, checkIncludeCmd); err != nil {
			return fmt.Errorf("sshd_config missing Include for /etc/ssh/sshd_config.d/*.conf: %w", err)
		}

		if err := runRootCmd(client, "sshd -t -f /etc/ssh/sshd_config"); err != nil {
			return fmt.Errorf("sshd config test failed: %w", err)
		}
		return nil

	case "firewall":
		logger.Debugf("handleValidate: kind=firewall\n")

		if err := runRootCmd(client, firewallIncludeCheckCmd); err != nil {
			logger.Warnf("nftables.conf missing include for /etc/nftables.d/*.nft (apply will enforce it)\n")
		}

		if err := runRootCmd(client, "nft -c -f /etc/nftables.conf"); err != nil {
			return fmt.Errorf("nftables config check failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported validate kind %q", kind)
	}
}
