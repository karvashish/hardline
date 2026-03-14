package rollbackutil

import (
	"encoding/base64"
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

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

func SnapshotRemoteFile(host pluginapi.Host, remotePath string) (rollback.FileSnapshot, error) {
	if host == nil {
		return rollback.FileSnapshot{}, fmt.Errorf("host is required")
	}

	snap := rollback.FileSnapshot{Path: remotePath}

	testCmd := "test -e " + strconv.Quote(remotePath)
	if err := host.RunRoot(testCmd); err != nil {
		snap.Existed = false
		return snap, nil
	}
	snap.Existed = true

	modeCmd := "stat -c %a " + strconv.Quote(remotePath)
	modeOut, err := host.RunRootWithOutput(modeCmd)
	if err != nil {
		return snap, err
	}
	snap.Mode = strings.TrimSpace(modeOut)

	content, err := host.ReadRootFile(remotePath)
	if err != nil {
		return snap, err
	}
	snap.ContentB64 = base64.StdEncoding.EncodeToString([]byte(content))
	return snap, nil
}

func SnapshotServiceState(host pluginapi.Host, unit string) (rollback.ServiceState, error) {
	if host == nil {
		return rollback.ServiceState{}, fmt.Errorf("host is required")
	}

	enabledOut, err := host.RunRootWithOutput("systemctl is-enabled " + strconv.Quote(unit) + " 2>/dev/null || true")
	if err != nil {
		return rollback.ServiceState{}, err
	}

	activeOut, err := host.RunRootWithOutput("systemctl is-active " + strconv.Quote(unit) + " 2>/dev/null || true")
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
