//go:build windows

package verify

import "os"

func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

var fileOwnerUID = func(os.FileInfo) (uint32, bool) {
	return 0, false
}
