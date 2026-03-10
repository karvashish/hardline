package remote

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/karvashish/hardline/pkg/logger"
	"golang.org/x/crypto/ssh"
)

func TestRunAndRunWithOutput(t *testing.T) {
	prevNewSession := newSession
	prevStdout := stdoutWriter
	prevStderr := stderrWriter
	prevDebug := logger.DebugMode()
	defer func() {
		newSession = prevNewSession
		stdoutWriter = prevStdout
		stderrWriter = prevStderr
		logger.SetDebug(prevDebug)
	}()

	sess := &fakeSession{}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	if err := Run(nil, "echo hi"); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if sess.cmd != "echo hi" {
		t.Fatalf("unexpected cmd %q", sess.cmd)
	}

	sess = &fakeSession{stdoutText: "ok"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	out, err := RunWithOutput(nil, "whoami")
	if err != nil || out != "ok" {
		t.Fatalf("unexpected RunWithOutput result out=%q err=%v", out, err)
	}
}

func TestRunErrorsAndDebugMode(t *testing.T) {
	prevNewSession := newSession
	prevStdout := stdoutWriter
	prevStderr := stderrWriter
	defer func() {
		newSession = prevNewSession
		stdoutWriter = prevStdout
		stderrWriter = prevStderr
	}()

	sess := &fakeSession{runErr: errors.New("boom"), stderrText: "bad"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if err := Run(nil, "x"); err == nil {
		t.Fatal("expected Run error")
	}

	stdoutWriter = testStdout{}
	stderrWriter = testStderr{}
	sess = &fakeSession{}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	logger.SetDebug(true)
	if err := Run(nil, "debug"); err != nil {
		t.Fatalf("Run debug failed: %v", err)
	}
	if !sess.stdoutIsOS || !sess.stderrIsOS {
		t.Fatal("expected debug mode to wire configured stdio")
	}
}

func TestRunRootVariants(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	sess := &fakeSession{stdoutText: "wrapped"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if err := RunRoot(nil, "id"); err != nil {
		t.Fatalf("RunRoot failed: %v", err)
	}
	if sess.cmd == "id" || !bytes.Contains([]byte(sess.cmd), []byte("sudo -n sh -lc")) {
		t.Fatalf("expected wrapped root cmd, got %q", sess.cmd)
	}

	sess = &fakeSession{stdoutText: "wrapped"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if _, err := RunRootWithOutput(nil, "id"); err != nil {
		t.Fatalf("RunRootWithOutput failed: %v", err)
	}
	if sess.cmd == "id" || !bytes.Contains([]byte(sess.cmd), []byte("sudo -n sh -lc")) {
		t.Fatalf("expected wrapped root cmd, got %q", sess.cmd)
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
