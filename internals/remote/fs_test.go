package remote

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestWriteRootFile(t *testing.T) {
	prevWrite := writeFileFn
	prevRunRoot := runRootFn
	prevNow := nowUnixNano
	defer func() {
		writeFileFn = prevWrite
		runRootFn = prevRunRoot
		nowUnixNano = prevNow
	}()

	nowUnixNano = func() int64 { return 123 }

	var gotPath string
	var gotMode os.FileMode
	writeFileFn = func(_ *sftp.Client, path string, _ []byte, mode os.FileMode) error {
		gotPath = path
		gotMode = mode
		return nil
	}
	var gotCmd string
	runRootFn = func(_ *ssh.Client, cmd string) error {
		gotCmd = cmd
		return nil
	}

	if err := WriteRootFile(nil, nil, "/etc/example", []byte("abc"), 0o644); err != nil {
		t.Fatalf("WriteRootFile failed: %v", err)
	}
	if gotPath != "/tmp/.hardline-123" || gotMode != 0o600 {
		t.Fatalf("unexpected temp write path=%q mode=%#o", gotPath, gotMode)
	}
	if !strings.Contains(gotCmd, "install -m 644 /tmp/.hardline-123 /etc/example") {
		t.Fatalf("unexpected root install cmd %q", gotCmd)
	}

	writeFileFn = func(_ *sftp.Client, path string, _ []byte, mode os.FileMode) error {
		return errors.New("write boom")
	}
	if err := WriteRootFile(nil, nil, "/etc/example", []byte("abc"), 0o644); err == nil {
		t.Fatal("expected WriteRootFile write error")
	}
}

func TestReadRootFile(t *testing.T) {
	prevNewFileSession := newFileSession
	defer func() { newFileSession = prevNewFileSession }()

	sess := &fakeFileSession{stdoutText: "content"}
	newFileSession = func(*ssh.Client) (fileSession, error) { return sess, nil }
	out, err := ReadRootFile(nil, "/etc/example")
	if err != nil || out != "content" {
		t.Fatalf("unexpected ReadRootFile result out=%q err=%v", out, err)
	}
	if !strings.Contains(sess.cmd, `sudo -n sh -lc "cat /etc/example"`) {
		t.Fatalf("unexpected read cmd %q", sess.cmd)
	}

	sess = &fakeFileSession{runErr: errors.New("boom"), stderrText: "bad"}
	newFileSession = func(*ssh.Client) (fileSession, error) { return sess, nil }
	if _, err := ReadRootFile(nil, "/etc/example"); err == nil {
		t.Fatal("expected ReadRootFile error")
	}
}

type fakeFileSession struct {
	cmd        string
	runErr     error
	stdout     io.Writer
	stderr     io.Writer
	stdoutText string
	stderrText string
}

func (s *fakeFileSession) Run(cmd string) error {
	s.cmd = cmd
	if s.stdout != nil && s.stdoutText != "" {
		_, _ = io.WriteString(s.stdout, s.stdoutText)
	}
	if s.stderr != nil && s.stderrText != "" {
		_, _ = io.WriteString(s.stderr, s.stderrText)
	}
	return s.runErr
}

func (s *fakeFileSession) Close() error { return nil }

func (s *fakeFileSession) SetWriters(stdout io.Writer, stderr io.Writer) {
	s.stdout = stdout
	s.stderr = stderr
}
