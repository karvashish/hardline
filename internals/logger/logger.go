package logger

import (
	"fmt"
	"os"
)

var debug bool

const (
	colorTag    = "\033[38;5;208m"
	colorDetail = "\033[38;5;246m"
	colorReset  = "\033[0m"
)

func SetDebug(enabled bool) {
	debug = enabled
}

func DebugMode() bool {
	return debug
}

func Debugf(format string, args ...any) {
	if !debug {
		return
	}
	fmt.Fprintf(os.Stderr,
		colorTag+"[debug] "+colorDetail+format+colorReset+"\n",
		args...,
	)
}

func Infof(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
