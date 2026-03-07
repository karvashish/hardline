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
			got, err := normalizeHostPort(tt.in)
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
	t.Run("missing file", func(t *testing.T) {
		_, err := loadKnownHostsCallback(Config{KnownHostsPath: filepath.Join(t.TempDir(), "missing_known_hosts")})
		if err == nil || !strings.Contains(err.Error(), "load known_hosts") {
			t.Fatalf("expected known_hosts load error, got %v", err)
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

	t.Run("known_hosts failure before dial", func(t *testing.T) {
		_, err := NewSSHClient(Config{
			User:           "u",
			Host:           "example.com",
			KeyPath:        keyPath,
			KnownHostsPath: filepath.Join(t.TempDir(), "missing_known_hosts"),
		})
		if err == nil || !strings.Contains(err.Error(), "load known_hosts") {
			t.Fatalf("expected known_hosts load error, got %v", err)
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
