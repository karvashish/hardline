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

type fakeSFTPFile struct {
	writeErr error
	chmodErr error
	closed   bool
	data     []byte
	mode     os.FileMode
}

func (f *fakeSFTPFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.data = append(f.data, p...)
	return len(p), nil
}

func (f *fakeSFTPFile) Close() error { f.closed = true; return nil }

func (f *fakeSFTPFile) Chmod(mode os.FileMode) error {
	f.mode = mode
	return f.chmodErr
}

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

func TestSSHFileSessionSetWriters(t *testing.T) {
	sess := sshFileSession{Session: &ssh.Session{}}
	var out, errOut io.Writer = io.Discard, io.Discard
	sess.SetWriters(out, errOut)
	if sess.Stdout != out || sess.Stderr != errOut {
		t.Fatal("expected writers to be assigned")
	}
}

func TestWriteFileWithStubbedOpen(t *testing.T) {
	client := &fakeSFTPFile{}
	if err := writeFileWithOpener(nil, "/tmp/x", []byte("abc"), 0o644, func(_ *sftp.Client, _ string) (remoteFile, error) {
		return client, nil
	}); err != nil {
		t.Fatalf("writeFileWithOpener failed: %v", err)
	}
	if string(client.data) != "abc" {
		t.Fatalf("unexpected data %q", string(client.data))
	}
	if client.mode != 0o644 {
		t.Fatalf("unexpected mode %#o", client.mode)
	}

	if err := writeFileWithOpener(nil, "/tmp/x", []byte("abc"), 0o644, func(_ *sftp.Client, _ string) (remoteFile, error) {
		return nil, errors.New("open boom")
	}); err == nil {
		t.Fatal("expected open error")
	}

	client = &fakeSFTPFile{writeErr: errors.New("write boom")}
	if err := writeFileWithOpener(nil, "/tmp/x", []byte("abc"), 0o644, func(_ *sftp.Client, _ string) (remoteFile, error) {
		return client, nil
	}); err == nil {
		t.Fatal("expected write error")
	}

	client = &fakeSFTPFile{chmodErr: errors.New("chmod boom")}
	if err := writeFileWithOpener(nil, "/tmp/x", []byte("abc"), 0o644, func(_ *sftp.Client, _ string) (remoteFile, error) {
		return client, nil
	}); err == nil {
		t.Fatal("expected chmod error")
	}
}

func TestReadRootFileSessionError(t *testing.T) {
	prevNewFileSession := newFileSession
	defer func() { newFileSession = prevNewFileSession }()

	newFileSession = func(*ssh.Client) (fileSession, error) { return nil, errors.New("session boom") }
	if _, err := ReadRootFile(nil, "/etc/x"); err == nil {
		t.Fatal("expected ReadRootFile session error")
	}
}

func TestCurrentUnixNano(t *testing.T) {
	if got := currentUnixNano(); got <= 0 {
		t.Fatalf("expected positive unix nano time, got %d", got)
	}
}

func TestWriteFilePanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = writeFile(nil, "/tmp/x", []byte("abc"), 0o644)
}

func TestNewSSHFileSessionPanicsOnNilClient(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	_, _ = newSSHFileSession(nil)
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
