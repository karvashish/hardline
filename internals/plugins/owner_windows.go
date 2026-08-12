//go:build windows

package plugins

import "os"

// fileOwnerUID has no answer on Windows, which carries no uid. External plugins
// are not supported there either - plugin.Open fails - so the mode and file-type
// checks are the whole trust check on that platform.
func fileOwnerUID(os.FileInfo) (uint32, bool) {
	return 0, false
}
