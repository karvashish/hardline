package executor

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

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
		return handleFirewall(client, p, s.Firewall)
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
		if err := runRoot(client, "apt-get update -y"); err != nil {
			return fmt.Errorf("apt-get update failed: %w", err)
		}
	}

	if pk.Upgrade {
		if err := runRoot(client, "apt-get upgrade -y"); err != nil {
			return fmt.Errorf("apt-get upgrade failed: %w", err)
		}
	}

	if len(pk.Install) > 0 {
		cmd := "apt-get install -y " + strings.Join(pk.Install, " ")
		if err := runRoot(client, cmd); err != nil {
			return fmt.Errorf("apt-get install failed (%s): %w", strings.Join(pk.Install, ","), err)
		}
	}

	if len(pk.Purge) > 0 {
		cmd := "apt-get purge -y " + strings.Join(pk.Purge, " ")
		if err := runRoot(client, cmd); err != nil {
			return fmt.Errorf("apt-get purge failed (%s): %w", strings.Join(pk.Purge, ","), err)
		}
	}

	if pk.Autoremove {
		if err := runRoot(client, "apt-get autoremove -y"); err != nil {
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

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	defer sftpClient.Close()

	mode := os.FileMode(0600)
	if t.Mode != "" {
		var parsed uint64
		if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err == nil {
			mode = os.FileMode(parsed)
		}
	}

	dir := path.Dir(t.Dest)
	if dir != "" && dir != "." {
		if err := runRoot(client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}

	if err := writeRootFile(client, sftpClient, t.Dest, data, mode); err != nil {
		return fmt.Errorf("writeRootFile %s: %w", t.Dest, err)
	}

	return nil
}

func canonicalServiceName(name string) string {
	if name == "sshd" {
		return "ssh"
	}
	return name
}

func handleService(client *ssh.Client, s *profile.ServiceSpec) error {
	if s.Name == "" {
		return fmt.Errorf("service name is required")
	}

	unit := canonicalServiceName(s.Name)
	logger.Debugf("handleService: name=%q unit=%q enabled=%v state=%q\n", s.Name, unit, s.Enabled, s.State)

	if s.Enabled != nil {
		var cmd string
		if *s.Enabled {
			cmd = fmt.Sprintf("systemctl enable %s", unit)
		} else {
			cmd = fmt.Sprintf("systemctl disable %s", unit)
		}
		if err := runRoot(client, cmd); err != nil {
			return fmt.Errorf("systemctl enable/disable %s: %w", unit, err)
		}
	}

	state := strings.ToLower(strings.TrimSpace(s.State))
	if state == "" {
		return nil
	}

	var cmd string
	switch state {
	case "started", "start":
		cmd = fmt.Sprintf("systemctl start %s", unit)
	case "stopped", "stop":
		cmd = fmt.Sprintf("systemctl stop %s", unit)
	case "restarted", "restart":
		cmd = fmt.Sprintf("systemctl restart %s", unit)
	case "reloaded", "reload", "reload-or-restart":
		cmd = fmt.Sprintf("systemctl reload-or-restart %s", unit)
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := runRoot(client, cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}

	return nil
}

func handleFirewall(client *ssh.Client, p *profile.Profile, fw *profile.FirewallSpec) error {
	logger.Debugf("handleFirewall: backend=%q allow_rules=%d\n", fw.Backend, len(fw.Allow))

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

	var lines []string
	for _, rule := range fw.Allow {
		proto := strings.ToLower(strings.TrimSpace(rule.Proto))
		if proto == "" {
			proto = "tcp"
		}
		lines = append(lines, fmt.Sprintf("    %s dport %d accept", proto, rule.Port))
	}
	allowBlock := strings.Join(lines, "\n")

	rendered := strings.Replace(string(tmplData), "{{allow_rules}}", allowBlock, 1)

	// allow firewall spec to override destination; fallback keeps old behavior
	destPath := strings.TrimSpace(fw.TemplateDest)
	if destPath == "" {
		destPath = "/etc/nftables.d/10-hardline.nft"
	}

	dir := path.Dir(destPath)
	if dir != "" && dir != "." {
		if err := runRoot(client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	defer sftpClient.Close()

	if err := writeRootFile(client, sftpClient, destPath, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("writeRootFile %s: %w", destPath, err)
	}
	return nil
}

func handleValidate(client *ssh.Client, kind string) error {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "sshd":
		logger.Debugf("handleValidate: kind=sshd\n")

		ensureIncludeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config || echo 'Include /etc/ssh/sshd_config.d/*.conf' >> /etc/ssh/sshd_config`
		if err := runRoot(client, ensureIncludeCmd); err != nil {
			return fmt.Errorf("ensure Include for sshd_config.d: %w", err)
		}

		if err := runRoot(client, "sshd -t -f /etc/ssh/sshd_config"); err != nil {
			return fmt.Errorf("sshd config test failed: %w", err)
		}
		return nil

	case "firewall":
		logger.Debugf("handleValidate: kind=firewall\n")

		ensureIncludeCmd := `grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf`
		if err := runRoot(client, ensureIncludeCmd); err != nil {
			return fmt.Errorf("ensure include for nftables.d: %w", err)
		}

		if err := runRoot(client, "nft -c -f /etc/nftables.conf"); err != nil {
			return fmt.Errorf("nftables config check failed: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported validate kind %q", kind)
	}
}
