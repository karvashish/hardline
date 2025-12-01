package executor

import (
	"fmt"
	"os"
	"strings"

	"github.com/karvashish/hardline/internals/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func applyProfile(client *ssh.Client, p *profile.Profile) error {
	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			if err := handleStep(client, p, step); err != nil {
				return err
			}
		}
	}
	return nil
}

func handleStep(client *ssh.Client, p *profile.Profile, s profile.Step) error {
	switch {
	case s.Packages != nil:
		return handlePackages(client, s.Packages)
	case s.Template != nil:
		return handleTemplate(client, p, s.Template)
	case s.Service != nil:
		return handleService(client, s.Service)
	case s.Sysctl != nil:
		return handleSysctl(client, s.Sysctl)
	case s.Firewall != nil:
		return handleFirewall(client, p, s.Firewall)
	default:
		// unknown / empty step; for now just warn
		fmt.Fprintln(os.Stderr, "warning: empty or unknown step")
		return nil
	}
}

func handlePackages(client *ssh.Client, pk *profile.PackageSpec) error {

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

	if err := writeRootFile(client, sftpClient, t.Dest, data, mode); err != nil {
		return fmt.Errorf("writeRootFile %s: %w", t.Dest, err)
	}

	ensureIncludeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config || echo 'Include /etc/ssh/sshd_config.d/*.conf' >> /etc/ssh/sshd_config`
	if err := runRoot(client, ensureIncludeCmd); err != nil {
		return fmt.Errorf("ensure Include for sshd_config.d: %w", err)
	}

	if err := runRoot(client, "sshd -t -f /etc/ssh/sshd_config"); err != nil {
		return fmt.Errorf("sshd -t failed: %w", err)
	}

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
	case "reloaded", "reload":
		cmd = fmt.Sprintf("systemctl reload %s", unit)
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := runRoot(client, cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}

	return nil
}

func handleSysctl(client *ssh.Client, s *profile.SysctlSpec) error {
	// TODO: for each key in s.Set, runRoot("sysctl -w key=value")
	fmt.Println("handleSysctl")
	return nil
}

func handleFirewall(client *ssh.Client, p *profile.Profile, fw *profile.FirewallSpec) error {
	// TODO: nftables rendering + apply, then service reload as needed
	fmt.Println("handleFirewall")
	return nil
}
