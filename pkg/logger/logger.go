package logger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var debug bool
var stderr io.Writer = os.Stderr
var mirror *lineMirror
var mirrorClock = func() time.Time { return time.Now().UTC() }
var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

const timestampFormat = "2006-01-02T15:04:05Z"

const (
	ColorTagDefault    = "\033[38;5;208m"
	ColorDetailDefault = "\033[38;5;246m"
	ColorReset         = "\033[0m"

	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"

	ColorBold = "\033[1m"
	ColorDim  = "\033[2m"
)

var debugTagColor = ColorTagDefault
var debugDetailColor = ColorDetailDefault

// lineMirror buffers writes until a newline arrives, then emits one
// ISO-8601-UTC-timestamped line to the underlying writer. Partial lines are
// flushed on close.
type lineMirror struct {
	mu  sync.Mutex
	w   io.Writer
	buf bytes.Buffer
}

func newLineMirror(w io.Writer) *lineMirror {
	return &lineMirror{w: w}
}

func (m *lineMirror) Write(msg string) {
	if m == nil || m.w == nil {
		return
	}
	clean := ansiPattern.ReplaceAllString(msg, "")
	if clean == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		idx := strings.IndexByte(clean, '\n')
		if idx < 0 {
			m.buf.WriteString(clean)
			return
		}
		m.buf.WriteString(clean[:idx])
		line := m.buf.String()
		m.buf.Reset()
		_, _ = fmt.Fprintf(m.w, "%s %s\n", mirrorClock().Format(timestampFormat), line)
		clean = clean[idx+1:]
		if clean == "" {
			return
		}
	}
}

func (m *lineMirror) Flush() {
	if m == nil || m.w == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.buf.Len() == 0 {
		return
	}
	_, _ = fmt.Fprintf(m.w, "%s %s\n", mirrorClock().Format(timestampFormat), m.buf.String())
	m.buf.Reset()
}

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

	tagColor := debugTagColor
	detailColor := debugDetailColor

	if strings.HasPrefix(format, "color=") {
		parts := strings.SplitN(format, " ", 2)
		if len(parts) == 2 {
			detailColor = strings.TrimPrefix(parts[0], "color=")
			format = parts[1]
		}
	}

	msg := fmt.Sprintf(format, args...)
	if mirror != nil {
		mirror.Write("[debug] " + msg)
		return
	}
	fmt.Fprint(stderr, tagColor+"[debug] "+detailColor+msg+ColorReset)
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
		mirror.Write(msg)
		return
	}

	fmt.Fprint(stderr, color+msg+ColorReset)
	mirror.Write(msg)
}

// Tickf writes transient progress output (throbber dots, spinners) to stderr
// only. Nothing is mirrored to the log file — log files would otherwise be
// flooded with progress noise.
func Tickf(format string, args ...any) {
	fmt.Fprintf(stderr, format, args...)
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
	mirror = newLineMirror(f)

	return func() {
		mirror.Flush()
		mirror = prevMirror
		_ = f.Close()
	}, nil
}
