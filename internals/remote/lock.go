package remote

import (
	"errors"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

// MutationLockDir is the single host-wide lock every hardline mutation takes.
// Apply and rollback both write the same files as root, so they share one lock
// rather than one each: two locks would let a rollback revert steps while an
// apply is still writing them.
const MutationLockDir = "/var/lib/hardline/.apply-lock.d"

// AcquireMutationLock claims the host mutation lock. mkdir is the primitive
// here because it is atomic on every filesystem hardline targets: the directory
// either did not exist and is now ours, or the command fails.
func AcquireMutationLock(client *Client) error {
	if client == nil {
		return nil
	}
	cmd := "mkdir -p /var/lib/hardline && mkdir " + pluginapi.ShellArg(MutationLockDir)
	if err := client.RunRoot(cmd); err != nil {
		return errors.New("another hardline apply or rollback is already running on this host; if stale, run: sudo rmdir " + MutationLockDir)
	}
	return nil
}

func ReleaseMutationLock(client *Client) error {
	if client == nil {
		return nil
	}
	return client.RunRoot("rmdir " + pluginapi.ShellArg(MutationLockDir))
}
