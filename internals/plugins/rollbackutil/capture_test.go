package rollbackutil

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestEnforceManagedPath(t *testing.T) {
	if err := EnforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.conf"); err != nil {
		t.Fatalf("expected managed path to pass: %v", err)
	}
	if err := EnforceManagedPath("/etc/nftables.d/99-hardline-firewall.nft"); err != nil {
		t.Fatalf("expected managed path to pass: %v", err)
	}

	cases := []struct {
		path    string
		wantErr string
	}{
		{path: "", wantErr: "empty"},
		{path: "/tmp/99-hardline-test.conf", wantErr: "outside /etc"},
		{path: "/etc/ssh/../sshd_config.d/99-hardline-ssh.conf", wantErr: "normalized"},
		{path: "/etc/ssh/sshd_config.d/10-ssh.conf", wantErr: "99-hardline"},
		{path: "/etc/ssh/sshd_config.d/99-hardline-ssh.txt", wantErr: "unsupported extension"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			err := EnforceManagedPath(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSnapshotRemoteFile(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		snap, err := SnapshotRemoteFile(rollbackHostStub{
			runRoot: func(string) error { return errors.New("not found") },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if snap.Existed {
			t.Fatalf("expected Existed=false, got %+v", snap)
		}
	})

	t.Run("host required", func(t *testing.T) {
		_, err := SnapshotRemoteFile(nil, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host-required error, got %v", err)
		}
	})

	t.Run("existing file", func(t *testing.T) {
		snap, err := SnapshotRemoteFile(rollbackHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644\n", nil },
			readRootFile:      func(string) (string, error) { return "abc", nil },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if !snap.Existed || snap.Mode != "644" || snap.ContentB64 != "YWJj" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	})

	t.Run("stat error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(rollbackHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "", errors.New("stat boom") },
			readRootFile:      func(string) (string, error) { return "", nil },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "stat boom") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(rollbackHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644", nil },
			readRootFile:      func(string) (string, error) { return "", errors.New("read boom") },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "read boom") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

func TestSnapshotServiceState(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		_, err := SnapshotServiceState(nil, "ssh")
		if err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host-required error, got %v", err)
		}
	})

	t.Run("known state", func(t *testing.T) {
		calls := 0
		state, err := SnapshotServiceState(rollbackHostStub{
			runRootWithOutput: func(string) (string, error) {
				calls++
				if calls == 1 {
					return "enabled\n", nil
				}
				return "active\n", nil
			},
		}, "ssh")
		if err != nil {
			t.Fatalf("SnapshotServiceState failed: %v", err)
		}
		if !state.Enabled || !state.Active || !state.Known || state.Unit != "ssh" {
			t.Fatalf("unexpected state: %+v", state)
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		state, err := SnapshotServiceState(rollbackHostStub{
			runRootWithOutput: func(string) (string, error) { return "\n", nil },
		}, "ssh")
		if err != nil {
			t.Fatalf("SnapshotServiceState failed: %v", err)
		}
		if state.Known {
			t.Fatalf("expected unknown state, got %+v", state)
		}
	})

	t.Run("enabled query error", func(t *testing.T) {
		_, err := SnapshotServiceState(rollbackHostStub{
			runRootWithOutput: func(string) (string, error) { return "", errors.New("enabled boom") },
		}, "ssh")
		if err == nil || !strings.Contains(err.Error(), "enabled boom") {
			t.Fatalf("expected enabled query error, got %v", err)
		}
	})

	t.Run("active query error", func(t *testing.T) {
		calls := 0
		_, err := SnapshotServiceState(rollbackHostStub{
			runRootWithOutput: func(string) (string, error) {
				calls++
				if calls == 1 {
					return "enabled", nil
				}
				return "", errors.New("active boom")
			},
		}, "ssh")
		if err == nil || !strings.Contains(err.Error(), "active boom") {
			t.Fatalf("expected active query error, got %v", err)
		}
	})
}

type rollbackHostStub struct {
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
}

func (s rollbackHostStub) RunRoot(cmd string) error {
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s rollbackHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput == nil {
		return "", nil
	}
	return s.runRootWithOutput(cmd)
}

func (rollbackHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not implemented") }

func (s rollbackHostStub) ReadRootFile(path string) (string, error) {
	if s.readRootFile == nil {
		return "", nil
	}
	return s.readRootFile(path)
}

func (rollbackHostStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

var _ pluginapi.Host = rollbackHostStub{}
