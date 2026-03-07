package rollbackutil

import (
	"encoding/base64"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/rollback"
	"golang.org/x/crypto/ssh"
)

type Deps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

func EnforceManagedPath(dest string) error {
	p := strings.TrimSpace(dest)
	if p == "" {
		return fmt.Errorf("managed destination path is empty")
	}
	if !strings.HasPrefix(p, "/etc/") {
		return fmt.Errorf("destination %q is outside /etc managed scope", p)
	}
	cleaned := path.Clean(p)
	if cleaned != p {
		return fmt.Errorf("destination %q is not a normalized absolute path", p)
	}

	base := path.Base(p)
	if !strings.HasPrefix(base, "99-hardline") {
		return fmt.Errorf("destination %q must use high-priority hardline prefix 99-hardline*", p)
	}

	ext := strings.ToLower(path.Ext(base))
	switch ext {
	case ".conf", ".nft", ".rules":
		return nil
	default:
		return fmt.Errorf("destination %q has unsupported extension %q", p, ext)
	}
}

func SnapshotRemoteFile(client *ssh.Client, remotePath string, deps Deps) (rollback.FileSnapshot, error) {
	snap := rollback.FileSnapshot{Path: remotePath}

	testCmd := "test -e " + strconv.Quote(remotePath)
	if err := deps.RunRoot(client, testCmd); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	modeCmd := "stat -c %a " + strconv.Quote(remotePath)
	modeOut, err := deps.RunRootWithOutput(client, modeCmd)
	if err != nil {
		return snap, err
	}
	snap.Mode = strings.TrimSpace(modeOut)

	content, err := deps.ReadRootFile(client, remotePath)
	if err != nil {
		return snap, err
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

func SnapshotServiceState(client *ssh.Client, unit string, deps Deps) (rollback.ServiceState, error) {
	enabledOut, err := deps.RunRootWithOutput(client, "systemctl is-enabled "+strconv.Quote(unit)+" 2>/dev/null || true")
	if err != nil {
		return rollback.ServiceState{}, err
	}

	activeOut, err := deps.RunRootWithOutput(client, "systemctl is-active "+strconv.Quote(unit)+" 2>/dev/null || true")
	if err != nil {
		return rollback.ServiceState{}, err
	}

	enabledVal := strings.TrimSpace(enabledOut)
	activeVal := strings.TrimSpace(activeOut)
	return rollback.ServiceState{
		Unit:    unit,
		Enabled: enabledVal == "enabled",
		Active:  activeVal == "active",
		Known:   enabledVal != "" || activeVal != "",
	}, nil
}
