package remote

import (
	"errors"
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const MutationLockDir = "/var/lib/hardline/.apply-lock.d"

const (
	lockTakenMarker = "hardline-lock-taken"
	lockHeldMarker  = "hardline-lock-held"
)

func AcquireMutationLock(client *Client) error {
	if client == nil {
		return nil
	}
	dir := pluginapi.ShellArg(MutationLockDir)
	cmd := "if { mkdir -p /var/lib/hardline && mkdir " + dir + "; } 2>&1; then echo " + lockTakenMarker +
		"; elif [ -d " + dir + " ]; then echo " + lockHeldMarker + "; fi"

	out, err := client.RunRootWithOutput(cmd)
	switch {
	case err != nil:
		return fmt.Errorf("take the hardline mutation lock on this host: %w", err)
	case strings.Contains(out, lockTakenMarker):
		return nil
	case strings.Contains(out, lockHeldMarker):
		return errors.New("another hardline apply or rollback is already running on this host; if stale, run: sudo rmdir " + MutationLockDir)
	default:
		return fmt.Errorf("take the hardline mutation lock on this host: %s", pluginapi.FirstLines(out, 3))
	}
}

func ReleaseMutationLock(client *Client) error {
	if client == nil {
		return nil
	}
	return client.RunRoot("rmdir " + pluginapi.ShellArg(MutationLockDir))
}
