package logger

import (
	"bytes"
	"strings"
	"testing"
)

func TestDebugAndInfoOutput(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
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
	defer func() { stderr = prevStderr }()

	var buf bytes.Buffer
	stderr = &buf

	Infof("color="+ColorCyan+" %s", "hello")
	if out := buf.String(); !strings.Contains(out, ColorCyan) || !strings.Contains(out, "hello") {
		t.Fatalf("unexpected colored info output %q", out)
	}
}

func TestDebugModeAndSetDebugColorsDefaults(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
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
	defer func() { stderr = prevStderr }()

	var buf bytes.Buffer
	stderr = &buf

	Infof("color="+ColorGreen, "ignored")
	if out := buf.String(); out != "color="+ColorGreen+"%!(EXTRA string=ignored)" {
		t.Fatalf("unexpected fallback output %q", out)
	}
}

func TestDebugfColorWithoutBodyDelimiterFallsBackToOriginalFormat(t *testing.T) {
	prevDebug := debug
	prevStderr := stderr
	prevColors := debugColors
	defer func() {
		debug = prevDebug
		stderr = prevStderr
		debugColors = prevColors
	}()

	var buf bytes.Buffer
	stderr = &buf
	SetDebug(true)

	Debugf("color="+ColorCyan, "ignored")
	out := buf.String()
	if !strings.Contains(out, "[debug]") || !strings.Contains(out, "color="+ColorCyan) {
		t.Fatalf("unexpected debug fallback output %q", out)
	}
}
