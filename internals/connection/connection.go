package connection

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type Config struct {
	KeyPath        string
	User           string
	Host           string
	KnownHostsPath string
}

var dialSSH = ssh.Dial

func NewSSHClient(cfg Config) (*ssh.Client, error) {
	user := strings.TrimSpace(cfg.User)
	if user == "" {
		return nil, fmt.Errorf("ssh user is required")
	}

	addr, err := normalizeHostPort(cfg.Host)
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

	client, err := dialSSH("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func normalizeHostPort(host string) (string, error) {
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

	return net.JoinHostPort(h, "22"), nil
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
		return nil, fmt.Errorf("load known_hosts %q: %w", knownHostsPath, err)
	}
	return callback, nil
}

func NewSFTPClient(client *ssh.Client) (*sftp.Client, error) {
	return sftp.NewClient(client)
}
