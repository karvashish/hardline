package connection

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/remote"
	"golang.org/x/crypto/ssh"
)

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "empty", in: "", wantErr: "ssh host is required"},
		{name: "hostname default port", in: "example.com", want: "example.com:22"},
		{name: "host with port", in: "example.com:2222", want: "example.com:2222"},
		{name: "bracketed ipv6 default port", in: "[::1]", want: "[::1]:22"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHostPort(tt.in, 0)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected address: got %q want %q", got, tt.want)
			}
		})
	}

	// Custom port tests
	portTests := []struct {
		name string
		host string
		port int
		want string
	}{
		{name: "custom port", host: "example.com", port: 2222, want: "example.com:2222"},
		{name: "custom port ipv6", host: "[::1]", port: 8022, want: "[::1]:8022"},
		{name: "explicit host:port overrides flag", host: "example.com:3333", port: 2222, want: "example.com:3333"},
	}
	for _, tt := range portTests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHostPort(tt.host, tt.port)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected address: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestResolveKnownHostsPath(t *testing.T) {
	t.Run("explicit config path", func(t *testing.T) {
		got, err := resolveKnownHostsPath(Config{KnownHostsPath: "/tmp/kh"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/tmp/kh" {
			t.Fatalf("unexpected path: %q", got)
		}
	})

	t.Run("env override", func(t *testing.T) {
		t.Setenv("HARDLINE_KNOWN_HOSTS", "/tmp/env-kh")
		got, err := resolveKnownHostsPath(Config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/tmp/env-kh" {
			t.Fatalf("unexpected path: %q", got)
		}
	})

	t.Run("default home path", func(t *testing.T) {
		t.Setenv("HARDLINE_KNOWN_HOSTS", "")
		home := t.TempDir()
		t.Setenv("HOME", home)

		got, err := resolveKnownHostsPath(Config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := filepath.Join(home, ".ssh", "known_hosts")
		if got != want {
			t.Fatalf("unexpected path: got %q want %q", got, want)
		}
	})
}

func TestLoadKnownHostsCallback(t *testing.T) {
	t.Run("missing file returns clear error", func(t *testing.T) {
		dir := t.TempDir()
		khPath := filepath.Join(dir, ".ssh", "missing_known_hosts")

		cb, err := loadKnownHostsCallback(Config{KnownHostsPath: khPath})
		if err == nil || !strings.Contains(err.Error(), "does not exist") || !strings.Contains(err.Error(), "ssh-keyscan") {
			t.Fatalf("expected clear missing known_hosts error, got callback=%v err=%v", cb, err)
		}
		if _, statErr := os.Stat(khPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected missing known_hosts file to stay missing, got stat err %v", statErr)
		}
	})

	t.Run("invalid file content", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "known_hosts")
		if err := os.WriteFile(path, []byte("not-a-valid-known-hosts-line\n"), 0o644); err != nil {
			t.Fatalf("write known_hosts: %v", err)
		}

		_, err := loadKnownHostsCallback(Config{KnownHostsPath: path})
		if err == nil || !strings.Contains(err.Error(), "load known_hosts") {
			t.Fatalf("expected known_hosts parse error, got %v", err)
		}
	})
}

func TestNewSSHClient_ValidationAndKeyErrors(t *testing.T) {
	if _, err := NewSSHClient(Config{User: "", Host: "example.com", KeyPath: "x"}); err == nil || !strings.Contains(err.Error(), "ssh user is required") {
		t.Fatalf("expected missing-user error, got %v", err)
	}
	if _, err := NewSSHClient(Config{User: "u", Host: "", KeyPath: "x"}); err == nil || !strings.Contains(err.Error(), "ssh host is required") {
		t.Fatalf("expected missing-host error, got %v", err)
	}

	if _, err := NewSSHClient(Config{User: "u", Host: "example.com", KeyPath: filepath.Join(t.TempDir(), "missing.key")}); err == nil {
		t.Fatal("expected missing private key read error")
	}

	invalidKey := filepath.Join(t.TempDir(), "invalid.key")
	if err := os.WriteFile(invalidKey, []byte("not-a-key"), 0o600); err != nil {
		t.Fatalf("write invalid key: %v", err)
	}
	if _, err := NewSSHClient(Config{User: "u", Host: "example.com", KeyPath: invalidKey}); err == nil {
		t.Fatal("expected private key parse error")
	}
}

func TestNewSSHClient_KnownHostsAndDialPaths(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id.key")
	writeEd25519PrivateKeyPEM(t, keyPath)

	t.Run("missing known_hosts fails before dial", func(t *testing.T) {
		khPath := filepath.Join(t.TempDir(), ".ssh", "missing_known_hosts")

		prevDial := dialSSH
		dialCalled := false
		dialSSH = func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
			dialCalled = true
			return nil, errors.New("dial boom")
		}
		t.Cleanup(func() { dialSSH = prevDial })

		_, err := NewSSHClient(Config{
			User:           "u",
			Host:           "example.com",
			KeyPath:        keyPath,
			KnownHostsPath: khPath,
		})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected missing known_hosts error, got %v", err)
		}
		if dialCalled {
			t.Fatal("expected missing known_hosts to fail before dial")
		}
		if _, statErr := os.Stat(khPath); !os.IsNotExist(statErr) {
			t.Fatalf("expected known_hosts file to remain absent, got stat err %v", statErr)
		}
	})

	t.Run("dial error with strict callback configured", func(t *testing.T) {
		knownHosts := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(knownHosts, nil, 0o644); err != nil {
			t.Fatalf("write known_hosts: %v", err)
		}

		prevDial := dialSSH
		dialSSH = func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
			if network != "tcp" {
				t.Fatalf("unexpected network: %q", network)
			}
			if addr != "example.com:22" {
				t.Fatalf("unexpected address: %q", addr)
			}
			if cfg == nil || cfg.HostKeyCallback == nil {
				t.Fatal("expected strict host key callback")
			}
			return nil, errors.New("dial boom")
		}
		t.Cleanup(func() { dialSSH = prevDial })

		_, err := NewSSHClient(Config{
			User:           "u",
			Host:           "example.com",
			KeyPath:        keyPath,
			KnownHostsPath: knownHosts,
		})
		if err == nil || !strings.Contains(err.Error(), "dial boom") {
			t.Fatalf("expected dial error, got %v", err)
		}
	})
}

func TestNewSSHClient_SudoPreflight(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id.key")
	writeEd25519PrivateKeyPEM(t, keyPath)

	knownHosts := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(knownHosts, nil, 0o644); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	t.Run("preflight failure", func(t *testing.T) {
		prevDial := dialSSH
		prevRunRoot := runRoot
		called := false

		dialSSH = func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
			return &ssh.Client{}, nil
		}
		runRoot = func(_ *remote.Client, cmd string) error {
			called = true
			if cmd != "true" {
				t.Fatalf("unexpected preflight command: %q", cmd)
			}
			return errors.New("sudo denied")
		}
		t.Cleanup(func() {
			dialSSH = prevDial
			runRoot = prevRunRoot
		})

		_, err := NewSSHClient(Config{
			User:           "u",
			Host:           "example.com",
			KeyPath:        keyPath,
			KnownHostsPath: knownHosts,
		})
		if !called {
			t.Fatal("expected preflight to run")
		}
		if err == nil || !strings.Contains(err.Error(), "sudo preflight failed") {
			t.Fatalf("expected sudo preflight error, got %v", err)
		}
	})

	t.Run("preflight success", func(t *testing.T) {
		prevDial := dialSSH
		prevRunRoot := runRoot

		dialSSH = func(network, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
			return &ssh.Client{}, nil
		}
		runRoot = func(_ *remote.Client, cmd string) error {
			if cmd != "true" {
				t.Fatalf("unexpected preflight command: %q", cmd)
			}
			return nil
		}
		t.Cleanup(func() {
			dialSSH = prevDial
			runRoot = prevRunRoot
		})

		got, err := NewSSHClient(Config{
			User:           "u",
			Host:           "example.com",
			KeyPath:        keyPath,
			KnownHostsPath: knownHosts,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil client returned")
		}
	})
}

func TestEnsureNonInteractiveSudo(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		if err := EnsureNonInteractiveSudo(nil); err != nil {
			t.Fatalf("expected nil client to pass, got %v", err)
		}
	})

	t.Run("run root failure", func(t *testing.T) {
		prevRunRoot := runRoot
		runRoot = func(_ *remote.Client, _ string) error { return errors.New("sudo denied") }
		t.Cleanup(func() { runRoot = prevRunRoot })

		err := EnsureNonInteractiveSudo(remote.New(&ssh.Client{}))
		if err == nil || !strings.Contains(err.Error(), "non-interactive sudo is required") {
			t.Fatalf("expected sudo preflight error, got %v", err)
		}
	})

	t.Run("run root success", func(t *testing.T) {
		prevRunRoot := runRoot
		called := false
		runRoot = func(_ *remote.Client, cmd string) error {
			called = true
			if cmd != "true" {
				t.Fatalf("unexpected command: %q", cmd)
			}
			return nil
		}
		t.Cleanup(func() { runRoot = prevRunRoot })

		if err := EnsureNonInteractiveSudo(remote.New(&ssh.Client{})); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if !called {
			t.Fatal("expected runRoot to be called")
		}
	})
}

func TestParseOSReleaseField(t *testing.T) {
	content := `PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
ID=ubuntu
ID_LIKE=debian
`
	tests := []struct {
		field string
		want  string
	}{
		{"ID", "ubuntu"},
		{"VERSION_ID", "24.04"},
		{"NAME", "Ubuntu"},
		{"MISSING", ""},
	}
	for _, tt := range tests {
		got := parseOSReleaseField(content, tt.field)
		if got != tt.want {
			t.Errorf("parseOSReleaseField(%q): got %q, want %q", tt.field, got, tt.want)
		}
	}
}

func TestCheckRemoteOS(t *testing.T) {
	t.Run("nil client always passes", func(t *testing.T) {
		if err := CheckRemoteOS(nil, "ubuntu", "24.04"); err != nil {
			t.Fatalf("expected nil client to pass, got %v", err)
		}
	})

	c := remote.New(&ssh.Client{})

	t.Run("empty family skips check", func(t *testing.T) {
		if err := CheckRemoteOS(c, "", "24.04"); err != nil {
			t.Fatalf("expected empty family to skip check, got %v", err)
		}
	})

	t.Run("os-release read error", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "", errors.New("sftp failed")
		}
		t.Cleanup(func() { runWithOutput = prev })

		err := CheckRemoteOS(c, "ubuntu", "24.04")
		if err == nil || !strings.Contains(err.Error(), "read remote OS info") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("family mismatch", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=debian\nVERSION_ID=\"12\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		err := CheckRemoteOS(c, "ubuntu", "24.04")
		if err == nil || !strings.Contains(err.Error(), "OS family mismatch") {
			t.Fatalf("expected family mismatch error, got %v", err)
		}
	})

	t.Run("version mismatch", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=ubuntu\nVERSION_ID=\"22.04\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		err := CheckRemoteOS(c, "ubuntu", "24.04")
		if err == nil || !strings.Contains(err.Error(), "OS version mismatch") {
			t.Fatalf("expected version mismatch error, got %v", err)
		}
	})

	t.Run("matching family and version", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=ubuntu\nVERSION_ID=\"24.04\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "ubuntu", "24.04"); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("matching family only, no version in profile", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=ubuntu\nVERSION_ID=\"24.04\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "ubuntu", ""); err != nil {
			t.Fatalf("expected success with no version requirement, got %v", err)
		}
	})

	t.Run("family match is case-insensitive", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=Ubuntu\nVERSION_ID=\"24.04\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "ubuntu", "24.04"); err != nil {
			t.Fatalf("expected case-insensitive match, got %v", err)
		}
	})

	t.Run("major-only declaration matches any point release", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=rocky\nVERSION_ID=\"9.6\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "rocky", "9"); err != nil {
			t.Fatalf("expected 9 to match 9.6, got %v", err)
		}
	})

	t.Run("major-only declaration does not match another major", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=rocky\nVERSION_ID=\"10.0\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "rocky", "9"); err == nil || !strings.Contains(err.Error(), "OS version mismatch") {
			t.Fatalf("expected version mismatch, got %v", err)
		}
	})

	t.Run("precise declaration is not widened", func(t *testing.T) {
		prev := runWithOutput
		runWithOutput = func(_ *remote.Client, _ string) (string, error) {
			return "ID=ubuntu\nVERSION_ID=\"24.10\"\n", nil
		}
		t.Cleanup(func() { runWithOutput = prev })

		if err := CheckRemoteOS(c, "ubuntu", "24.04"); err == nil || !strings.Contains(err.Error(), "OS version mismatch") {
			t.Fatalf("expected 24.04 to reject 24.10, got %v", err)
		}
	})
}

func TestVersionMatches(t *testing.T) {
	cases := []struct {
		declared string
		remote   string
		want     bool
	}{
		{"9", "9.6", true},
		{"9", "9", true},
		{"9", "10.0", false},
		{"9", "19.1", false},
		{"24.04", "24.04", true},
		{"24.04", "24.04.1", true},
		{"24.04", "24.10", false},
		{"24.04", "24", false},
		{"42", "42", true},
	}
	for _, tc := range cases {
		if got := versionMatches(tc.declared, tc.remote); got != tc.want {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", tc.declared, tc.remote, got, tc.want)
		}
	}
}

func writeEd25519PrivateKeyPEM(t *testing.T, path string) {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	p := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, p, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
}
