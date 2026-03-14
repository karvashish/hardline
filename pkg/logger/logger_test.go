package logger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugAndInfoOutput(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	stderr = &buf

	SetDebug(false)
	Debugf("hidden %s", "msg")
	if buf.Len() != 0 {
		t.Fatalf("expected no debug output when disabled, got %q", buf.String())
	}

	SetDebug(true)
	SetDebugColors(ColorBlue, ColorGreen)
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

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = &mirrorBuf

	Infof("color="+ColorCyan+" %s", "hello")
	if out := buf.String(); !strings.Contains(out, ColorCyan) || !strings.Contains(out, "hello") {
		t.Fatalf("unexpected colored info output %q", out)
	}
	if out := mirrorBuf.String(); out != "hello" {
		t.Fatalf("unexpected mirrored info output %q", out)
	}
}

func TestDebugModeAndSetDebugColorsDefaults(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	stderr = &buf

	SetDebug(false)
	if DebugMode() {
		t.Fatal("expected debug mode disabled")
	}

	SetDebug(true)
	if !DebugMode() {
		t.Fatal("expected debug mode enabled")
	}

	original := debugColors
	SetDebugColors("", "")
	if debugColors != original {
		t.Fatal("expected empty debug colors to preserve current colors")
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

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = &mirrorBuf

	Infof("color="+ColorGreen, "ignored")
	if out := buf.String(); out != "color="+ColorGreen+"%!(EXTRA string=ignored)" {
		t.Fatalf("unexpected fallback output %q", out)
	}
	if out := mirrorBuf.String(); out != "color=%!(EXTRA string=ignored)" {
		t.Fatalf("unexpected mirrored fallback output %q", out)
	}
}

func TestDebugfColorWithoutBodyDelimiterFallsBackToOriginalFormat(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	prevMirror := mirror
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
		mirror = prevMirror
	}()

	var buf bytes.Buffer
	var mirrorBuf bytes.Buffer
	stderr = &buf
	mirror = &mirrorBuf
	SetDebug(true)

	Debugf("color="+ColorCyan, "ignored")
	out := buf.String()
	if !strings.Contains(out, "[debug]") || !strings.Contains(out, "color="+ColorCyan) {
		t.Fatalf("unexpected debug fallback output %q", out)
	}
	if out := mirrorBuf.String(); out != "[debug] color=%!(EXTRA string=ignored)" {
		t.Fatalf("unexpected mirrored debug fallback output %q", out)
	}
}

func TestUseLogFile(t *testing.T) {
	prevMirror := mirror
	prevStderr := stderr
	defer func() {
		mirror = prevMirror
		stderr = prevStderr
	}()

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
	if string(data) != "hello\n" {
		t.Fatalf("unexpected log file contents %q", string(data))
	}
	if mirror != prevMirror {
		t.Fatal("expected mirror to be restored after close")
	}
}
