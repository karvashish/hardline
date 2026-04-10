package logger

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const frozenTimestamp = "2024-01-02T03:04:05Z"

func freezeClock(t *testing.T) {
	t.Helper()
	prev := mirrorClock
	mirrorClock = func() time.Time {
		return time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	}
	t.Cleanup(func() { mirrorClock = prev })
}

func TestDebugAndInfoOutput(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevTagColor := debugTagColor
	prevDetailColor := debugDetailColor
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugTagColor = prevTagColor
		debugDetailColor = prevDetailColor
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	stderr = &buf
	mirror = nil

	SetDebug(false)
	Debugf("hidden %s", "msg")
	if buf.Len() != 0 {
		t.Fatalf("expected no debug output when disabled, got %q", buf.String())
	}

	SetDebug(true)
	Debugf("visible %s", "msg")
	if out := buf.String(); !strings.Contains(out, "[debug]") || !strings.Contains(out, "visible msg") {
		t.Fatalf("unexpected debug output %q", out)
	}

	buf.Reset()
	Infof("plain %s", "text")
	if out := buf.String(); out != "plain text" {
		t.Fatalf("unexpected plain info output %q", out)
	}

	buf.Reset()
	Warnf("warn")
	if out := buf.String(); !strings.Contains(out, ColorYellow) || !strings.Contains(out, "warn") {
		t.Fatalf("unexpected warn output %q", out)
	}

	buf.Reset()
	Errorf("err")
	if out := buf.String(); !strings.Contains(out, ColorRed) || !strings.Contains(out, "err") {
		t.Fatalf("unexpected error output %q", out)
	}
}

func TestColorPrefixParsing(t *testing.T) {
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		stderr = prevStderr
		mirror = prevMirror
	}()
	freezeClock(t)

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = newLineMirror(&mirrorBuf)

	Infof("color="+ColorCyan+" %s\n", "hello")
	if out := buf.String(); !strings.Contains(out, ColorCyan) || !strings.Contains(out, "hello") {
		t.Fatalf("unexpected colored info output %q", out)
	}
	want := frozenTimestamp + " hello\n"
	if out := mirrorBuf.String(); out != want {
		t.Fatalf("unexpected mirrored info output %q (want %q)", out, want)
	}
}

func TestDebugModeToggle(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	stderr = &buf
	mirror = nil

	SetDebug(false)
	if DebugMode() {
		t.Fatal("expected debug mode disabled")
	}

	SetDebug(true)
	if !DebugMode() {
		t.Fatal("expected debug mode enabled")
	}

	Debugf("plain %s", "debug")
	if out := buf.String(); !strings.Contains(out, "[debug]") || !strings.Contains(out, "plain debug") {
		t.Fatalf("unexpected debug output %q", out)
	}
}

func TestInfofColorWithoutBodyDelimiterFallsBackToPlain(t *testing.T) {
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		stderr = prevStderr
		mirror = prevMirror
	}()
	freezeClock(t)

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = newLineMirror(&mirrorBuf)

	Infof("color="+ColorGreen, "ignored")
	mirror.Flush()
	if out := buf.String(); out != "color="+ColorGreen+"%!(EXTRA string=ignored)" {
		t.Fatalf("unexpected fallback output %q", out)
	}
	want := frozenTimestamp + " color=%!(EXTRA string=ignored)\n"
	if out := mirrorBuf.String(); out != want {
		t.Fatalf("unexpected mirrored fallback output %q (want %q)", out, want)
	}
}

func TestDebugfColorWithoutBodyDelimiterFallsBackToOriginalFormat(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevTagColor := debugTagColor
	prevDetailColor := debugDetailColor
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugTagColor = prevTagColor
		debugDetailColor = prevDetailColor
		mirror = prevMirror
	}()
	freezeClock(t)

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = newLineMirror(&mirrorBuf)
	SetDebug(true)

	Debugf("color="+ColorCyan, "ignored")
	mirror.Flush()

	if out := buf.String(); out != "" {
		t.Fatalf("expected empty terminal when mirror active, got %q", out)
	}
	want := frozenTimestamp + " [debug] color=%!(EXTRA string=ignored)\n"
	if out := mirrorBuf.String(); out != want {
		t.Fatalf("unexpected mirrored debug fallback output %q (want %q)", out, want)
	}
}

func TestDebugRoutesToMirrorOnlyWhenLogFileActive(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		mirror = prevMirror
	}()
	freezeClock(t)

	var termBuf bytes.Buffer
	var fileBuf bytes.Buffer
	stderr = &termBuf
	mirror = newLineMirror(&fileBuf)
	SetDebug(true)

	Debugf("routed %s\n", "message")

	if termBuf.Len() != 0 {
		t.Fatalf("expected terminal clean when log file active, got %q", termBuf.String())
	}
	want := frozenTimestamp + " [debug] routed message\n"
	if out := fileBuf.String(); out != want {
		t.Fatalf("expected debug in log file %q, got %q", want, out)
	}

	termBuf.Reset()
	fileBuf.Reset()
	Infof("progress %s\n", "line")
	if out := termBuf.String(); out != "progress line\n" {
		t.Fatalf("expected progress on terminal, got %q", out)
	}
	want = frozenTimestamp + " progress line\n"
	if out := fileBuf.String(); out != want {
		t.Fatalf("expected progress in log file %q, got %q", want, out)
	}
}

func TestTickfBypassesMirror(t *testing.T) {
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		stderr = prevStderr
		mirror = prevMirror
	}()

	var termBuf bytes.Buffer
	var fileBuf bytes.Buffer
	stderr = &termBuf
	mirror = newLineMirror(&fileBuf)

	Tickf(".")
	Tickf(".")
	Tickf(".")

	if out := termBuf.String(); out != "..." {
		t.Fatalf("expected dots on terminal, got %q", out)
	}
	if fileBuf.Len() != 0 {
		t.Fatalf("expected tick output to bypass mirror, got %q", fileBuf.String())
	}
}

func TestLineMirrorBuffersPartialLines(t *testing.T) {
	prevMirror := mirror
	defer func() { mirror = prevMirror }()
	freezeClock(t)

	var fileBuf bytes.Buffer
	mirror = newLineMirror(&fileBuf)

	mirror.Write("step: foo ")
	if fileBuf.Len() != 0 {
		t.Fatalf("expected partial line to stay buffered, got %q", fileBuf.String())
	}
	mirror.Write("done\n")
	want := frozenTimestamp + " step: foo done\n"
	if out := fileBuf.String(); out != want {
		t.Fatalf("unexpected mirror output %q (want %q)", out, want)
	}
}

func TestLineMirrorFlushesRemainderOnClose(t *testing.T) {
	prevMirror := mirror
	defer func() { mirror = prevMirror }()
	freezeClock(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "out.log")

	closeLog, err := UseLogFile(path)
	if err != nil {
		t.Fatalf("UseLogFile: %v", err)
	}
	Infof("no newline here")
	closeLog()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	want := frozenTimestamp + " no newline here\n"
	if string(data) != want {
		t.Fatalf("unexpected log contents %q (want %q)", string(data), want)
	}
}

func TestUseLogFile(t *testing.T) {
	prevMirror := mirror
	prevStderr := stderr
	defer func() {
		mirror = prevMirror
		stderr = prevStderr
	}()
	freezeClock(t)

	var stderrBuf bytes.Buffer
	stderr = &stderrBuf

	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "hardline.log")

	closeLog, err := UseLogFile(path)
	if err != nil {
		t.Fatalf("UseLogFile failed: %v", err)
	}
	Infof("color="+ColorGreen+" %s\n", "hello")
	closeLog()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	want := frozenTimestamp + " hello\n"
	if string(data) != want {
		t.Fatalf("unexpected log file contents %q (want %q)", string(data), want)
	}
	if mirror != prevMirror {
		t.Fatal("expected mirror to be restored after close")
	}
}

func TestUseLogFileEmptyPath(t *testing.T) {
	closer, err := UseLogFile("")
	if err != nil {
		t.Fatalf("expected no error for empty path, got %v", err)
	}
	closer()
}

func TestUseLogFileInvalidPath(t *testing.T) {
	_, err := UseLogFile("/dev/null/impossible/path.log")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestWrap(t *testing.T) {
	base := errors.New("boom")

	err := Wrap(base, "connect failed")
	if err == nil {
		t.Fatal("expected wrapped error")
	}
	if got := err.Error(); got != "connect failed: boom" {
		t.Fatalf("unexpected wrapped error text %q", got)
	}
	if !errors.Is(err, base) {
		t.Fatal("expected wrapped error to unwrap to base error")
	}
}

func TestDebugfColorPrefixWithoutMirror(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	stderr = &buf
	mirror = nil
	SetDebug(true)

	Debugf("color="+ColorCyan+" %s", "colored")
	if out := buf.String(); !strings.Contains(out, "[debug]") || !strings.Contains(out, "colored") {
		t.Fatalf("unexpected debug output %q", out)
	}
}
