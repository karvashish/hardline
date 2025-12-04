package logger

import (
	"fmt"
	"os"
	"strings"
)

var debug bool

const (
	colorTagDefault    = "\033[38;5;208m"
	colorDetailDefault = "\033[38;5;246m"
	colorReset         = "\033[0m"

	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorBold   = "\033[1m"
	ColorDim    = "\033[2m"
)

type DebugColors struct {
	TagColor    string
	DetailColor string
}

var debugColors = DebugColors{
	TagColor:    colorTagDefault,
	DetailColor: colorDetailDefault,
}

func SetDebug(enabled bool) {
	debug = enabled
}

func DebugMode() bool {
	return debug
}

func SetDebugColors(tag string, detail string) {
	if tag != "" {
		debugColors.TagColor = tag
	}
	if detail != "" {
		debugColors.DetailColor = detail
	}
}

func Debugf(format string, args ...any) {
	if !debug {
		return
	}

	tagColor := debugColors.TagColor
	detailColor := debugColors.DetailColor

	if strings.HasPrefix(format, "color=") {
		parts := strings.SplitN(format, " ", 2)
		if len(parts) == 2 {
			detailColor = strings.TrimPrefix(parts[0], "color=")
			format = parts[1]
		}
	}

	fmt.Fprintf(os.Stderr,
		tagColor+"[debug] "+detailColor+format+colorReset+"\n",
		args...,
	)
}

func Infof(format string, args ...any) {
	color := ""
	if strings.HasPrefix(format, "color=") {
		parts := strings.SplitN(format, " ", 2)
		if len(parts) == 2 {
			color = strings.TrimPrefix(parts[0], "color=")
			format = parts[1]
		}
	}

	if color == "" {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
		return
	}

	fmt.Fprintf(os.Stderr, color+format+colorReset+"\n", args...)
}
