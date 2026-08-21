//go:build windows

package verify

import "os"

func fileOwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}
