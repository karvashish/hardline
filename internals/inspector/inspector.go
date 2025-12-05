package inspector

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/karvashish/hardline/internals/remote"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Inspector interface {
	PackageInstalled(name string) bool
	AptAutoremovePreview() ([]string, error)
	Stat(path string) (os.FileInfo, error)
	IsServiceEnabled(unit string) bool
	IsServiceActive(unit string) bool

	SSHIncludePresent() bool
	SSHConfigTest() error

	FirewallIncludePresent() bool
	FirewallConfigTest() error
}

type SSHInspector struct {
	client *ssh.Client
}

func NewSSHInspector(client *ssh.Client) *SSHInspector {
	return &SSHInspector{client: client}
}

func (i *SSHInspector) PackageInstalled(name string) bool {
	cmd := fmt.Sprintf("dpkg -s %q >/dev/null 2>&1", name)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) AptAutoremovePreview() ([]string, error) {
	cmd := "DEBIAN_FRONTEND=noninteractive apt-get -s autoremove"

	out, err := remote.RunRootWithOutput(i.client, cmd)
	if err != nil {
		return nil, err
	}

	var pkgs []string
	seen := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "Remv ") && !strings.HasPrefix(line, "Remv\t") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pkgs, nil
}

func (i *SSHInspector) Stat(path string) (os.FileInfo, error) {
	sftpClient, err := sftp.NewClient(i.client)
	if err != nil {
		return nil, err
	}
	defer sftpClient.Close()

	return sftpClient.Stat(path)
}

func (i *SSHInspector) IsServiceEnabled(unit string) bool {
	cmd := fmt.Sprintf("systemctl is-enabled %s >/dev/null 2>&1", unit)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) IsServiceActive(unit string) bool {
	cmd := fmt.Sprintf("systemctl is-active %s >/dev/null 2>&1", unit)
	err := remote.RunRoot(i.client, cmd)
	return err == nil
}

func (i *SSHInspector) SSHIncludePresent() bool {
	includeCmd := `grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config`
	err := remote.RunRoot(i.client, includeCmd)
	return err == nil
}

func (i *SSHInspector) SSHConfigTest() error {
	return remote.RunRoot(i.client, "sshd -t -f /etc/ssh/sshd_config")
}

func (i *SSHInspector) FirewallIncludePresent() bool {
	includeCmd := `grep -q 'include "/etc/nftables.d/*.nft"' /etc/nftables.conf`
	err := remote.RunRoot(i.client, includeCmd)
	return err == nil
}

func (i *SSHInspector) FirewallConfigTest() error {
	return remote.RunRoot(i.client, "nft -c -f /etc/nftables.conf")
}
