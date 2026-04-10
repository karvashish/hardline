package remote

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func TestRunAndRunWithOutput(t *testing.T) {
	prevNewSession := newSession
	prevDebug := logger.DebugMode()
	defer func() {
		newSession = prevNewSession
		logger.SetDebug(prevDebug)
	}()

	sess := &fakeSession{}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	c := New(nil)
	if err := c.Run("echo hi"); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if sess.cmd != "echo hi" {
		t.Fatalf("unexpected cmd %q", sess.cmd)
	}

	sess = &fakeSession{stdoutText: "ok"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	out, err := c.RunWithOutput("whoami")
	if err != nil || out != "ok" {
		t.Fatalf("unexpected RunWithOutput result out=%q err=%v", out, err)
	}
}

func TestRunErrorsAndDebugMode(t *testing.T) {
	prevNewSession := newSession
	prevDebug := logger.DebugMode()
	defer func() {
		newSession = prevNewSession
		logger.SetDebug(prevDebug)
	}()

	c := New(nil)
	sess := &fakeSession{runErr: errors.New("boom"), stderrText: "bad"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if err := c.Run("x"); err == nil {
		t.Fatal("expected Run error")
	}

	sess = &fakeSession{stdoutText: "some output"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	logger.SetDebug(true)
	if err := c.Run("debug"); err != nil {
		t.Fatalf("Run debug failed: %v", err)
	}

	if sess.stdoutIsOS || sess.stderrIsOS {
		t.Fatal("expected debug mode to use buffered capture, not raw OS stdio")
	}
}

func TestSSHSessionSetWriters(t *testing.T) {
	sess := sshSession{Session: &ssh.Session{}}
	var out, errOut io.Writer = io.Discard, io.Discard
	sess.SetWriters(out, errOut)
	if sess.Stdout != out || sess.Stderr != errOut {
		t.Fatal("expected writers to be assigned")
	}
}

func TestRunNewSessionError(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	newSession = func(*ssh.Client) (session, error) { return nil, errors.New("session boom") }
	c := New(nil)
	if err := c.Run("x"); err == nil {
		t.Fatal("expected Run to fail on session creation")
	}
	if _, err := c.RunWithOutput("x"); err == nil {
		t.Fatal("expected RunWithOutput to fail on session creation")
	}
}

func TestRunWithOutputReturnsStdoutOnCommandError(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	sess := &fakeSession{runErr: errors.New("boom"), stdoutText: "partial", stderrText: "bad"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	out, err := New(nil).RunWithOutput("x")
	if err == nil {
		t.Fatal("expected RunWithOutput error")
	}
	if out != "partial" {
		t.Fatalf("unexpected partial output %q", out)
	}
}

func TestRunWithOutputTimeout(t *testing.T) {
	prevNewSession := newSession
	prevTimeout := DefaultCmdTimeout
	defer func() {
		newSession = prevNewSession
		DefaultCmdTimeout = prevTimeout
	}()

	DefaultCmdTimeout = 10 * time.Millisecond
	sess := &blockingSession{unblock: make(chan struct{})}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	_, err := New(nil).RunWithOutput("slow")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestRunWithOutputDebugLogging(t *testing.T) {
	prevNewSession := newSession
	prevDebug := logger.DebugMode()
	defer func() {
		newSession = prevNewSession
		logger.SetDebug(prevDebug)
	}()

	logger.SetDebug(true)
	sess := &fakeSession{stdoutText: "debug output"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	out, err := New(nil).RunWithOutput("debug-cmd")
	if err != nil {
		t.Fatalf("RunWithOutput failed: %v", err)
	}
	if out != "debug output" {
		t.Fatalf("unexpected output %q", out)
	}
}

func TestRunRootVariants(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	c := New(nil)
	sess := &fakeSession{stdoutText: "wrapped"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if err := c.RunRoot("id"); err != nil {
		t.Fatalf("RunRoot failed: %v", err)
	}
	if sess.cmd == "id" || !bytes.Contains([]byte(sess.cmd), []byte("sudo -n sh -lc")) {
		t.Fatalf("expected wrapped root cmd, got %q", sess.cmd)
	}

	sess = &fakeSession{stdoutText: "wrapped"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if _, err := c.RunRootWithOutput("id"); err != nil {
		t.Fatalf("RunRootWithOutput failed: %v", err)
	}
	if sess.cmd == "id" || !bytes.Contains([]byte(sess.cmd), []byte("sudo -n sh -lc")) {
		t.Fatalf("expected wrapped root cmd, got %q", sess.cmd)
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("echo $HOME"); got != "'echo $HOME'" {
		t.Fatalf("unexpected shellQuote result %q", got)
	}
	if got := shellQuote("printf '%s' $HOME"); got != `'printf '"'"'%s'"'"' $HOME'` {
		t.Fatalf("unexpected shellQuote result %q", got)
	}
}

type fakeSession struct {
	cmd        string
	runErr     error
	stdout     io.Writer
	stderr     io.Writer
	stdoutText string
	stderrText string
	stdoutIsOS bool
	stderrIsOS bool
}

func (s *fakeSession) Run(cmd string) error {
	s.cmd = cmd
	if s.stdout != nil && s.stdoutText != "" {
		_, _ = io.WriteString(s.stdout, s.stdoutText)
	}
	if s.stderr != nil && s.stderrText != "" {
		_, _ = io.WriteString(s.stderr, s.stderrText)
	}
	return s.runErr
}

func (s *fakeSession) Close() error { return nil }

func (s *fakeSession) SetWriters(stdout io.Writer, stderr io.Writer) {
	s.stdout = stdout
	s.stderr = stderr
	_, s.stdoutIsOS = stdout.(testStdout)
	_, s.stderrIsOS = stderr.(testStderr)
}

type testStdout struct{}
type testStderr struct{}

func (testStdout) Write(p []byte) (int, error) { return len(p), nil }
func (testStderr) Write(p []byte) (int, error) { return len(p), nil }

type blockingSession struct {
	unblock chan struct{}
}

func (s *blockingSession) Run(cmd string) error {
	<-s.unblock
	return errors.New("session closed")
}

func (s *blockingSession) Close() error {
	select {
	case <-s.unblock:
	default:
		close(s.unblock)
	}
	return nil
}

func (s *blockingSession) SetWriters(stdout io.Writer, stderr io.Writer) {}
