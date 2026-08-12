//go:build !windows

package plugins

import (
	"os"
	"syscall"
)

// fileOwnerUID reports the owning uid of an already-stat'd path. The second
// result is false when the platform does not carry one, which is the only case
// where the ownership half of the trust check is skipped.
func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, false
	}
	return stat.Uid, true
}
