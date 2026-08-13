package remote

import (
	"errors"
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
	prevGen := generateTempSuffix
	prevNewSession := newSession
	prevNewSFTPWriter := newSFTPWriter
	defer func() {
		writeFileFn = prevWrite
		generateTempSuffix = prevGen
		newSession = prevNewSession
		newSFTPWriter = prevNewSFTPWriter
	}()

	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	generateTempSuffix = func() (string, error) { return "deadbeef", nil }

	var gotPath string
	var gotMode os.FileMode
	writeFileFn = func(_ *sftp.Client, path string, _ []byte, mode os.FileMode) error {
		gotPath = path
		gotMode = mode
		return nil
	}
	sess := &fakeSession{}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }

	if err := New(nil).WriteRootFile("/etc/example", []byte("abc"), 0o644); err != nil {
		t.Fatalf("WriteRootFile failed: %v", err)
	}
	if gotPath != "/tmp/.hardline-deadbeef" || gotMode != 0o600 {
		t.Fatalf("unexpected temp write path=%q mode=%#o", gotPath, gotMode)
	}
	wantInstall := `'install -m 644 -- '"'"'/tmp/.hardline-deadbeef'"'"' '"'"'/etc/example'"'"' && rm -f -- '"'"'/tmp/.hardline-deadbeef'"'"''`
	if !strings.Contains(sess.cmd, wantInstall) {
		t.Fatalf("unexpected root install cmd %q", sess.cmd)
	}

	generateTempSuffix = func() (string, error) { return "", errors.New("rand boom") }
	if err := New(nil).WriteRootFile("/etc/example", []byte("abc"), 0o644); err == nil || !strings.Contains(err.Error(), "generate temp path") {
		t.Fatalf("expected temp path error, got %v", err)
	}

	generateTempSuffix = func() (string, error) { return "deadbeef", nil }
	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) { return nil, errors.New("writer boom") }
	if err := New(nil).WriteRootFile("/etc/example", []byte("abc"), 0o644); err == nil || !strings.Contains(err.Error(), "writer boom") {
		t.Fatalf("expected writer error, got %v", err)
	}

	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	writeFileFn = func(_ *sftp.Client, path string, _ []byte, mode os.FileMode) error {
		return errors.New("write boom")
	}
	if err := New(nil).WriteRootFile("/etc/example", []byte("abc"), 0o644); err == nil {
		t.Fatal("expected WriteRootFile write error")
	}
}

func TestWriteRootFileRunRootError(t *testing.T) {
	prevWrite := writeFileFn
	prevGen := generateTempSuffix
	prevNewSession := newSession
	prevNewSFTPWriter := newSFTPWriter
	defer func() {
		writeFileFn = prevWrite
		generateTempSuffix = prevGen
		newSession = prevNewSession
		newSFTPWriter = prevNewSFTPWriter
	}()

	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	generateTempSuffix = func() (string, error) { return "deadbeef", nil }
	writeFileFn = func(_ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }
	newSession = func(*ssh.Client) (session, error) {
		return &fakeSession{runErr: errors.New("install boom"), stderrText: "bad"}, nil
	}

	if err := New(nil).WriteRootFile("/etc/example", []byte("abc"), 0o644); err == nil {
		t.Fatal("expected WriteRootFile to fail on install error")
	}
}

func TestReadRootFile(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	sess := &fakeSession{stdoutText: "content"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	out, err := New(nil).ReadRootFile("/etc/example")
	if err != nil || out != "content" {
		t.Fatalf("unexpected ReadRootFile result out=%q err=%v", out, err)
	}
	if !strings.Contains(sess.cmd, "sudo -n sh -lc") || !strings.Contains(sess.cmd, "cat") || !strings.Contains(sess.cmd, "/etc/example") {
		t.Fatalf("unexpected read cmd %q", sess.cmd)
	}

	sess = &fakeSession{runErr: errors.New("boom"), stderrText: "bad"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if _, err := New(nil).ReadRootFile("/etc/example"); err == nil {
		t.Fatal("expected ReadRootFile error")
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
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	newSession = func(*ssh.Client) (session, error) { return nil, errors.New("session boom") }
	if _, err := New(nil).ReadRootFile("/etc/x"); err == nil {
		t.Fatal("expected ReadRootFile session error")
	}
}

func TestDefaultGenerateTempSuffix(t *testing.T) {
	s, err := defaultGenerateTempSuffix()
	if err != nil {
		t.Fatalf("defaultGenerateTempSuffix failed: %v", err)
	}
	if len(s) != 16 {
		t.Fatalf("expected 16 hex chars, got %q (len=%d)", s, len(s))
	}
	s2, _ := defaultGenerateTempSuffix()
	if s == s2 {
		t.Fatal("expected two calls to produce different suffixes")
	}

	prev := cryptoRandRead
	defer func() { cryptoRandRead = prev }()
	cryptoRandRead = func(b []byte) (int, error) { return 0, errors.New("rand boom") }
	if _, err := defaultGenerateTempSuffix(); err == nil || err.Error() != "rand boom" {
		t.Fatalf("expected rand error, got %v", err)
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

func TestReadRootFileQuotesPath(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	sess := &fakeSession{stdoutText: "ok"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	_, err := New(nil).ReadRootFile("/etc/my file.conf")
	if err != nil {
		t.Fatalf("ReadRootFile failed: %v", err)
	}
	if !strings.Contains(sess.cmd, "cat") || !strings.Contains(sess.cmd, "/etc/my file.conf") {
		t.Fatalf("expected quoted path in cmd, got %q", sess.cmd)
	}
}
