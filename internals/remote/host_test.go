package remote

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/profile"
	"golang.org/x/crypto/ssh"
)

func TestClient_RunMethods(t *testing.T) {
	prevNewSession := newSession
	defer func() { newSession = prevNewSession }()

	c := New(nil)

	sess := &fakeSession{stdoutText: "root"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	if err := c.RunRoot("id"); err != nil {
		t.Fatalf("RunRoot failed: %v", err)
	}
	if !strings.Contains(sess.cmd, "sudo -n sh -lc") || !strings.Contains(sess.cmd, "id") {
		t.Fatalf("unexpected wrapped cmd: %q", sess.cmd)
	}

	sess = &fakeSession{stdoutText: "root"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	out, err := c.RunRootWithOutput("whoami")
	if err != nil || out != "root" {
		t.Fatalf("unexpected RunRootWithOutput out=%q err=%v", out, err)
	}

	sess = &fakeSession{stdoutText: "ok"}
	newSession = func(*ssh.Client) (session, error) { return sess, nil }
	out, err = c.RunRootWithTimeout("apt-get update", 30*time.Second)
	if err != nil || out != "ok" {
		t.Fatalf("unexpected RunRootWithTimeout out=%q err=%v", out, err)
	}
}

func TestClient_StatWithFakeSFTP(t *testing.T) {
	prevNewSFTP := newSFTPClient
	defer func() { newSFTPClient = prevNewSFTP }()

	newSFTPClient = func(*ssh.Client) (sftpStatClient, error) {
		return fakeSFTPClient{info: fakeFileInfo{mode: 0o644, size: 12}}, nil
	}
	info, err := New(nil).Stat("/etc/example")
	if err != nil || info.Size() != 12 || info.Mode() != 0o644 {
		t.Fatalf("unexpected Stat result: info=%+v err=%v", info, err)
	}

	newSFTPClient = func(*ssh.Client) (sftpStatClient, error) {
		return nil, errors.New("boom")
	}
	if _, err := New(nil).Stat("/etc/example"); err == nil || err.Error() != "boom" {
		t.Fatalf("expected sftp error, got %v", err)
	}
}

func TestClient_Close(t *testing.T) {
	if err := New(nil).Close(); err != nil {
		t.Fatalf("Close on nil client should be a no-op, got %v", err)
	}
	var c *Client
	if err := c.Close(); err != nil {
		t.Fatalf("Close on nil receiver should be a no-op, got %v", err)
	}
}

func TestBuildContext(t *testing.T) {
	p := &profile.Profile{ID: "ctx-test"}
	p.SetRuntimeOverrides(map[string]json.RawMessage{"key": json.RawMessage(`"val"`)})

	ctx := BuildContext(nil, p, nil)
	if ctx.Host != nil {
		t.Fatal("expected nil host for nil client")
	}
	if ctx.Profile != p {
		t.Fatal("expected profile to match")
	}
	if string(ctx.Overrides["key"]) != `"val"` {
		t.Fatalf("unexpected overrides: %v", ctx.Overrides)
	}
	if ctx.StepChanges != nil {
		t.Fatal("expected nil step changes")
	}

	c := New(&ssh.Client{})
	changes := map[string]bool{"s1": true}
	ctx = BuildContext(c, p, changes)
	if ctx.Host == nil {
		t.Fatal("expected non-nil host for real client")
	}
	if !ctx.StepChanges["s1"] {
		t.Fatal("expected step changes to pass through")
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
