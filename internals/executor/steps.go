package executor

import (
	"fmt"
	"os"
	"sort"
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
		cmd = fmt.Sprintf("systemctl reload-or-restart %s", unit)
	default:
		return fmt.Errorf("unsupported service state %q for %s", s.State, unit)
	}

	if err := runRoot(client, cmd); err != nil {
		return fmt.Errorf("systemctl %s %s: %w", state, unit, err)
	}

	return nil
}

func handleSysctl(client *ssh.Client, s *profile.SysctlSpec) error {
	if len(s.Set) == 0 {
		return nil
	}

	// 1) Show existing values before modification (debug-friendly)
	keys := make([]string, 0, len(s.Set))
	for k := range s.Set {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	checkCmd := "sysctl " + joinKeys(keys)
	if err := runRoot(client, checkCmd); err != nil {
		return fmt.Errorf("sysctl check: %w", err)
	}

	// 2) Apply each sysctl setting
	for _, key := range keys {
		val := s.Set[key]
		cmd := fmt.Sprintf("sysctl -w %s=%s", key, val)

		if err := runRoot(client, cmd); err != nil {
			return fmt.Errorf("sysctl set %s=%s: %w", key, val, err)
		}
	}

	return nil
}

// joinKeys turns ["a","b","c"] into "a b c"
func joinKeys(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	out := keys[0]
	for _, k := range keys[1:] {
		out += " " + k
	}
	return out
}

func handleFirewall(client *ssh.Client, p *profile.Profile, fw *profile.FirewallSpec) error {
	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}

	// 1) load nftables base template from profile
	tmplData, err := p.LoadTemplate("templates/nftables_base.tmpl")
	if err != nil {
		return fmt.Errorf("load nftables template: %w", err)
	}

	// 2) build allow rules block
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

	// 3) ensure /etc/nftables.d exists
	if err := runRoot(client, `mkdir -p /etc/nftables.d`); err != nil {
		return fmt.Errorf("mkdir /etc/nftables.d: %w", err)
	}

	// 4) SFTP client
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	defer sftpClient.Close()

	// 5) write hardline nftables snippet
	const nftSnippetPath = "/etc/nftables.d/10-hardline.nft"
	if err := writeRootFile(client, sftpClient, nftSnippetPath, []byte(rendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("writeRootFile %s: %w", nftSnippetPath, err)
	}

	// 6) ensure /etc/nftables.conf includes the snippets directory
	ensureIncludeCmd := `grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf`
	if err := runRoot(client, ensureIncludeCmd); err != nil {
		return fmt.Errorf("ensure include for nftables.d: %w", err)
	}

	// 7) validate full nftables config
	if err := runRoot(client, "nft -c -f /etc/nftables.conf"); err != nil {
		return fmt.Errorf("nftables config check failed: %w", err)
	}

	return nil
}
