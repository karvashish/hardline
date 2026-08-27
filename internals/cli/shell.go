package cli

import "strings"

// Command hints are printed to be pasted, so any value that is not a bare shell word has to
// survive the shell that re-parses it.
func ShellArg(s string) string {
	if s != "" && isShellSafe(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func isShellSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("-_./:=@%+,", r):
		default:
			return false
		}
	}
	return true
}
