//go:build windows

package plugins

import "os"

func fileOwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}
