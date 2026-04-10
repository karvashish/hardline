package connection

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/karvashish/hardline/internals/remote"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Config struct {
	KeyPath        string
	User           string
	Host           string
	Port           int
	KnownHostsPath string
}

var (
	dialSSH       = ssh.Dial
	runRoot       = (*remote.Client).RunRoot
	runWithOutput = (*remote.Client).RunWithOutput
)

func NewSSHClient(cfg Config) (*remote.Client, error) {
	user := strings.TrimSpace(cfg.User)
	if user == "" {
		return nil, fmt.Errorf("ssh user is required")
	}

	addr, err := normalizeHostPort(cfg.Host, cfg.Port)
	if err != nil {
		return nil, err
	}

	key, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := loadKnownHostsCallback(cfg)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	sshClient, err := dialSSH("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	client := remote.New(sshClient)
	if err := EnsureNonInteractiveSudo(client); err != nil {
		return nil, fmt.Errorf("sudo preflight failed: %w", err)
	}

	return client, nil
}

func normalizeHostPort(host string, port int) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", fmt.Errorf("ssh host is required")
	}

	if _, _, err := net.SplitHostPort(h); err == nil {
		return h, nil
	}

	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
	}

	p := "22"
	if port > 0 {
		p = fmt.Sprintf("%d", port)
	}

	return net.JoinHostPort(h, p), nil
}

func resolveKnownHostsPath(cfg Config) (string, error) {
	if p := strings.TrimSpace(cfg.KnownHostsPath); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("HARDLINE_KNOWN_HOSTS")); p != "" {
		return p, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home for known_hosts: %w", err)
	}
	return filepath.Join(homeDir, ".ssh", "known_hosts"), nil
}

func loadKnownHostsCallback(cfg Config) (ssh.HostKeyCallback, error) {
	knownHostsPath, err := resolveKnownHostsPath(cfg)
	if err != nil {
		return nil, err
	}
	callback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf(
				`known_hosts file %q does not exist; create and populate it first (for example: ssh-keyscan <host> >> %s) or set HARDLINE_KNOWN_HOSTS`,
				knownHostsPath, knownHostsPath,
			)
		}
		return nil, fmt.Errorf("load known_hosts %q: %w", knownHostsPath, err)
	}
	return callback, nil
}

func EnsureNonInteractiveSudo(client *remote.Client) error {
	if client == nil {
		return nil
	}
	if err := runRoot(client, "true"); err != nil {
		return fmt.Errorf("non-interactive sudo is required (configure passwordless sudo or use root): %w", err)
	}
	return nil
}

// CheckRemoteOS reads /etc/os-release from the remote host and verifies that
// the OS family and version match the profile declaration. If the profile does
// not declare a family, the check is skipped. Version is only checked when
// the profile specifies one.
func CheckRemoteOS(client *remote.Client, family, version string) error {
	if client == nil || strings.TrimSpace(family) == "" {
		return nil
	}
	out, err := runWithOutput(client, "cat /etc/os-release")
	if err != nil {
		return fmt.Errorf("read remote OS info (/etc/os-release): %w", err)
	}
	remoteFamily := parseOSReleaseField(out, "ID")
	remoteVersion := parseOSReleaseField(out, "VERSION_ID")
	if !strings.EqualFold(remoteFamily, strings.TrimSpace(family)) {
		return fmt.Errorf(
			"OS family mismatch: profile requires %q, remote reports %q",
			family, remoteFamily,
		)
	}
	if v := strings.TrimSpace(version); v != "" && remoteVersion != v {
		return fmt.Errorf(
			"OS version mismatch: profile requires %q, remote reports %q",
			version, remoteVersion,
		)
	}
	return nil
}

func parseOSReleaseField(content, field string) string {
	prefix := field + "="
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		val := strings.TrimPrefix(line, prefix)
		val = strings.Trim(val, `"`)
		return strings.TrimSpace(val)
	}
	return ""
}
