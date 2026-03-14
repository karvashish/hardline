package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var debug bool
var stderr io.Writer = os.Stderr
var mirror io.Writer
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const (
	ColorTagDefault    = "\033[38;5;208m"
	ColorDetailDefault = "\033[38;5;246m"
	ColorReset         = "\033[0m"

	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"

	ColorBold = "\033[1m"
	ColorDim  = "\033[2m"

	ColorBrightRed     = "\033[91m"
	ColorBrightGreen   = "\033[92m"
	ColorBrightYellow  = "\033[93m"
	ColorBrightBlue    = "\033[94m"
	ColorBrightMagenta = "\033[95m"
	ColorBrightCyan    = "\033[96m"
	ColorBrightWhite   = "\033[97m"

	ColorGray     = "\033[38;5;244m"
	ColorDarkGray = "\033[38;5;240m"
	ColorOrange   = "\033[38;5;208m"
	ColorTeal     = "\033[38;5;37m"
	ColorPink     = "\033[38;5;213m"
)

type DebugColors struct {
	TagColor    string
	DetailColor string
}

var debugColors = DebugColors{
	TagColor:    ColorTagDefault,
	DetailColor: ColorDetailDefault,
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

	msg := fmt.Sprintf(format, args...)
	fmt.Fprint(stderr, tagColor+"[debug] "+detailColor+msg+ColorReset)
	writeMirror("[debug] " + msg)
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

	msg := fmt.Sprintf(format, args...)

	if color == "" {
		fmt.Fprint(stderr, msg)
		writeMirror(msg)
		return
	}

	fmt.Fprint(stderr, color+msg+ColorReset)
	writeMirror(msg)
}

func Warnf(format string, args ...any) {
	Infof("color="+ColorYellow+" "+format, args...)
}

func Errorf(format string, args ...any) {
	Infof("color="+ColorRed+" "+format, args...)
}

func UseLogFile(path string) (func(), error) {
	if strings.TrimSpace(path) == "" {
		return func() {}, nil
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}

	prevMirror := mirror
	mirror = f

	return func() {
		mirror = prevMirror
		_ = f.Close()
	}, nil
}

func writeMirror(msg string) {
	if mirror == nil {
		return
	}
	_, _ = io.WriteString(mirror, ansiPattern.ReplaceAllString(msg, ""))
}
