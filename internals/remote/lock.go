package remote

import (
	"errors"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const MutationLockDir = "/var/lib/hardline/.apply-lock.d"

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
