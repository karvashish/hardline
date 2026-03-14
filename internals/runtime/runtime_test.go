package runtime

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestSSHRuntime_RunAndReadDelegation(t *testing.T) {
	prevRunRoot := runRoot
	prevRunRootOut := runRootWithOutput
	prevReadRoot := readRootFile
	prevWriteRoot := writeRootFile
	prevNewSFTP := newSFTPClient
	prevNewSFTPWriter := newSFTPWriter
	defer func() {
		runRoot = prevRunRoot
		runRootWithOutput = prevRunRootOut
		readRootFile = prevReadRoot
		writeRootFile = prevWriteRoot
		newSFTPClient = prevNewSFTP
		newSFTPWriter = prevNewSFTPWriter
	}()

	runCalled := false
	runRoot = func(_ *ssh.Client, cmd string) error {
		runCalled = cmd == "echo hi"
		return nil
	}
	runRootWithOutput = func(_ *ssh.Client, cmd string) (string, error) {
		if cmd != "whoami" {
			return "", errors.New("unexpected command")
		}
		return "root", nil
	}
	readRootFile = func(_ *ssh.Client, path string) (string, error) {
		if path != "/etc/example" {
			return "", errors.New("unexpected path")
		}
		return "content", nil
	}

	rt := NewSSHRuntime(nil)
	if err := rt.RunRoot("echo hi"); err != nil {
		t.Fatalf("RunRoot failed: %v", err)
	}
	if !runCalled {
		t.Fatal("expected RunRoot delegation")
	}
	out, err := rt.RunRootWithOutput("whoami")
	if err != nil || out != "root" {
		t.Fatalf("unexpected RunRootWithOutput result: out=%q err=%v", out, err)
	}
	text, err := rt.ReadRootFile("/etc/example")
	if err != nil || text != "content" {
		t.Fatalf("unexpected ReadRootFile result: out=%q err=%v", text, err)
	}

	writeCalled := false
	writeRootFile = func(_ *ssh.Client, _ *sftp.Client, path string, data []byte, mode os.FileMode) error {
		writeCalled = path == "/etc/example" && string(data) == "next" && mode == 0o640
		return nil
	}
	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) { return nil, nil }
	if err := rt.WriteRootFile("/etc/example", []byte("next"), 0o640); err != nil {
		t.Fatalf("WriteRootFile failed: %v", err)
	}
	if !writeCalled {
		t.Fatal("expected WriteRootFile delegation")
	}

	newSFTPClient = func(*ssh.Client) (sftpStatClient, error) {
		return fakeSFTPClient{info: fakeFileInfo{mode: 0o644, size: 12}}, nil
	}
	info, err := rt.Stat("/etc/example")
	if err != nil || info.Size() != 12 || info.Mode() != 0o644 {
		t.Fatalf("unexpected Stat result: info=%+v err=%v", info, err)
	}
}

func TestSSHRuntime_StatWithFakeSFTP(t *testing.T) {
	prevNewSFTP := newSFTPClient
	prevNewSFTPWriter := newSFTPWriter
	prevWriteRoot := writeRootFile
	defer func() {
		newSFTPClient = prevNewSFTP
		newSFTPWriter = prevNewSFTPWriter
		writeRootFile = prevWriteRoot
	}()

	newSFTPClient = func(*ssh.Client) (sftpStatClient, error) {
		return nil, errors.New("boom")
	}

	rt := NewSSHRuntime(nil)
	if _, err := rt.Stat("/etc/example"); err == nil || err.Error() != "boom" {
		t.Fatalf("expected sftp error, got %v", err)
	}

	newSFTPWriter = func(*ssh.Client) (*sftp.Client, error) {
		return nil, errors.New("writer boom")
	}
	if err := rt.WriteRootFile("/etc/example", []byte("x"), 0o600); err == nil || err.Error() != "writer boom" {
		t.Fatalf("expected writer error, got %v", err)
	}
}

func TestFakeFileInfoShape(t *testing.T) {
	info := fakeFileInfo{mode: 0o644, size: 12}
	if info.Name() != "x" || info.Size() != 12 || info.Mode() != 0o644 || info.IsDir() {
		t.Fatalf("unexpected fake file info: %+v", info)
	}
	if info.ModTime() != time.Unix(0, 0) || info.Sys() != nil {
		t.Fatalf("unexpected fake file info metadata: %+v", info)
	}
}

type fakeFileInfo struct {
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return "x" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

type fakeSFTPClient struct {
	info os.FileInfo
	err  error
}

func (c fakeSFTPClient) Stat(string) (os.FileInfo, error) {
	return c.info, c.err
}

func (fakeSFTPClient) Close() error { return nil }
