package remote

import "strings"

func shellQuote(cmd string) string {
	return "'" + strings.ReplaceAll(cmd, "'", "'\"'\"'") + "'"
}
