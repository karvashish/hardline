package pluginapi

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEnforceManagedPath(t *testing.T) {
	if err := EnforceManagedPath("/etc/ssh/sshd_config.d/99-hardline-ssh.conf"); err != nil {
		t.Fatalf("expected managed path to pass: %v", err)
	}
	if err := EnforceManagedPath("/etc/nftables.d/99-hardline-firewall.nft"); err != nil {
		t.Fatalf("expected managed path to pass: %v", err)
	}
	// sshd keeps the first value obtained from its lexically expanded includes,
	// so a managed drop-in there has to sort before any vendor or cloud-init
	// file rather than after it.
	if err := EnforceManagedPath("/etc/ssh/sshd_config.d/00-hardline-ssh.conf"); err != nil {
		t.Fatalf("expected an early-ordering managed path to pass: %v", err)
	}

	cases := []struct {
		path    string
		wantErr string
	}{
		{path: "", wantErr: "empty"},
		{path: "/tmp/99-hardline-test.conf", wantErr: "outside /etc"},
		{path: "/etc/ssh/../sshd_config.d/99-hardline-ssh.conf", wantErr: "normalized"},
		{path: "/etc/ssh/sshd_config.d/10-ssh.conf", wantErr: "hardline prefix"},
		{path: "/etc/ssh/sshd_config.d/50-cloud-init.conf", wantErr: "hardline prefix"},
		// Only the two hardline prefixes are accepted; a plausible-looking
		// middle number is not a managed file.
		{path: "/etc/ssh/sshd_config.d/01-hardline-ssh.conf", wantErr: "hardline prefix"},
		{path: "/etc/ssh/sshd_config.d/99-hardline-ssh.txt", wantErr: "unsupported extension"},
		{path: "/etc/ssh/sshd_config.d/00-hardline-ssh.txt", wantErr: "unsupported extension"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			err := EnforceManagedPath(tc.path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestSnapshotRemoteFile(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		_, err := SnapshotRemoteFile(nil, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host-required error, got %v", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		snap, err := SnapshotRemoteFile(pluginAPIHostStub{
			runRoot: func(string) error { return errors.New("not found") },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if snap.Existed {
			t.Fatalf("expected Existed=false, got %+v", snap)
		}
	})

	t.Run("existing file", func(t *testing.T) {
		snap, err := SnapshotRemoteFile(pluginAPIHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644\n", nil },
			readRootFile:      func(string) (string, error) { return "abc", nil },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if !snap.Existed || snap.Mode != "644" || snap.ContentB64 != "YWJj" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	})

	t.Run("stat error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(pluginAPIHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "", errors.New("stat boom") },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "stat boom") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(pluginAPIHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644", nil },
			readRootFile:      func(string) (string, error) { return "", errors.New("read boom") },
		}, "/etc/ssh/sshd_config.d/99-hardline-ssh.conf")
		if err == nil || !strings.Contains(err.Error(), "read boom") {
			t.Fatalf("expected read error, got %v", err)
		}
	})
}

type pluginAPIHostStub struct {
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s pluginAPIHostStub) RunRoot(cmd string) error {
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s pluginAPIHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput == nil {
		return "", nil
	}
	return s.runRootWithOutput(cmd)
}

func (s pluginAPIHostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

func (pluginAPIHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("not implemented") }

func (s pluginAPIHostStub) ReadRootFile(path string) (string, error) {
	if s.readRootFile == nil {
		return "", nil
	}
	return s.readRootFile(path)
}

func (s pluginAPIHostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile == nil {
		return nil
	}
	return s.writeRootFile(path, data, mode)
}

var _ Host = pluginAPIHostStub{}

func TestCapturesDiffer(t *testing.T) {
	file := func(existed bool, content string) CaptureResult {
		return CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFile, File: &FileSnapshot{Existed: existed, ContentB64: content}}}}
	}
	svc := func(active, enabled bool) CaptureResult {
		return CaptureResult{Objects: []ObjectRecord{{Kind: ObjectService, Service: &ServiceState{Active: active, Enabled: enabled}}}}
	}
	pkg := func(installed bool) CaptureResult {
		return CaptureResult{Objects: []ObjectRecord{{Kind: ObjectPackage, Package: &PackageState{WasInstalled: installed}}}}
	}

	if CapturesDiffer(file(true, "abc"), file(true, "abc")) {
		t.Fatal("identical file snapshots should not differ")
	}
	if !CapturesDiffer(file(false, ""), file(true, "abc")) {
		t.Fatal("absent→present file should differ")
	}
	if !CapturesDiffer(file(true, "abc"), file(true, "xyz")) {
		t.Fatal("changed content should differ")
	}
	if CapturesDiffer(svc(true, true), svc(true, true)) {
		t.Fatal("identical service states should not differ")
	}
	if !CapturesDiffer(svc(false, false), svc(true, true)) {
		t.Fatal("service state change should differ")
	}
	if CapturesDiffer(pkg(true), pkg(true)) {
		t.Fatal("identical package states should not differ")
	}
	if !CapturesDiffer(pkg(false), pkg(true)) {
		t.Fatal("package install change should differ")
	}

	a := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFile, File: &FileSnapshot{}}}}
	b := CaptureResult{Objects: []ObjectRecord{}}
	if !CapturesDiffer(a, b) {
		t.Fatal("different object counts should differ")
	}
}

const managedTestPath = "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"

func TestRestoreFileSnapshot(t *testing.T) {
	t.Run("unmanaged path rejected", func(t *testing.T) {
		err := RestoreFileSnapshot(pluginAPIHostStub{}, FileSnapshot{Path: "/tmp/99-hardline.conf", Existed: true})
		if err == nil || !strings.Contains(err.Error(), "outside /etc") {
			t.Fatalf("expected managed-path error, got %v", err)
		}
	})

	t.Run("absent file removed", func(t *testing.T) {
		var got string
		err := RestoreFileSnapshot(pluginAPIHostStub{
			runRoot: func(cmd string) error { got = cmd; return nil },
		}, FileSnapshot{Path: managedTestPath, Existed: false})
		if err != nil {
			t.Fatalf("RestoreFileSnapshot failed: %v", err)
		}
		if !strings.HasPrefix(got, "rm -f ") || !strings.Contains(got, managedTestPath) {
			t.Fatalf("expected rm -f command, got %q", got)
		}
	})

	t.Run("existing file rewritten", func(t *testing.T) {
		var gotData []byte
		var gotMode os.FileMode
		err := RestoreFileSnapshot(pluginAPIHostStub{
			runRoot: func(string) error { return nil },
			writeRootFile: func(_ string, data []byte, mode os.FileMode) error {
				gotData = data
				gotMode = mode
				return nil
			},
		}, FileSnapshot{
			Path:       managedTestPath,
			Existed:    true,
			Mode:       "640",
			ContentB64: base64.StdEncoding.EncodeToString([]byte("hello")),
		})
		if err != nil {
			t.Fatalf("RestoreFileSnapshot failed: %v", err)
		}
		if string(gotData) != "hello" || gotMode != os.FileMode(0o640) {
			t.Fatalf("unexpected write: data=%q mode=%o", gotData, gotMode)
		}
	})

	t.Run("bad content decode", func(t *testing.T) {
		err := RestoreFileSnapshot(pluginAPIHostStub{
			runRoot: func(string) error { return nil },
		}, FileSnapshot{Path: managedTestPath, Existed: true, ContentB64: "!!!not-base64!!!"})
		if err == nil || !strings.Contains(err.Error(), "decode snapshot content") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})
}

func TestFileSnapshotConflict(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("expected"))

	if c := FileSnapshotConflict(pluginAPIHostStub{}, FileSnapshot{Path: managedTestPath, Existed: false}); c != nil {
		t.Fatalf("absent file should report no conflict, got %v", c)
	}

	if c := FileSnapshotConflict(pluginAPIHostStub{}, FileSnapshot{Path: managedTestPath, Existed: true, ContentB64: "!!!"}); c != nil {
		t.Fatalf("undecodable journal content should be skipped, got %v", c)
	}

	readErr := FileSnapshotConflict(pluginAPIHostStub{
		readRootFile: func(string) (string, error) { return "", errors.New("nope") },
	}, FileSnapshot{Path: managedTestPath, Existed: true, ContentB64: encoded})
	if len(readErr) != 1 || !strings.Contains(readErr[0], "cannot be read") {
		t.Fatalf("expected read conflict, got %v", readErr)
	}

	drift := FileSnapshotConflict(pluginAPIHostStub{
		readRootFile: func(string) (string, error) { return "tampered", nil },
	}, FileSnapshot{Path: managedTestPath, Existed: true, ContentB64: encoded})
	if len(drift) != 1 || !strings.Contains(drift[0], "differs") {
		t.Fatalf("expected drift conflict, got %v", drift)
	}

	if c := FileSnapshotConflict(pluginAPIHostStub{
		readRootFile: func(string) (string, error) { return "expected", nil },
	}, FileSnapshot{Path: managedTestPath, Existed: true, ContentB64: encoded}); c != nil {
		t.Fatalf("matching content should report no conflict, got %v", c)
	}
}

func TestCapturesDifferFileMeta(t *testing.T) {
	meta := func(s FileMetaSnapshot) CaptureResult {
		return CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFileMeta, FileMeta: &s}}}
	}
	base := FileMetaSnapshot{Existed: true, Mode: "640", Owner: "root", Group: "root", Attrs: "i"}

	if CapturesDiffer(meta(base), meta(base)) {
		t.Fatal("identical metadata should not differ")
	}
	mutations := []FileMetaSnapshot{
		{Existed: true, Mode: "600", Owner: "root", Group: "root", Attrs: "i"},
		{Existed: true, Mode: "640", Owner: "bin", Group: "root", Attrs: "i"},
		{Existed: true, Mode: "640", Owner: "root", Group: "bin", Attrs: "i"},
		{Existed: true, Mode: "640", Owner: "root", Group: "root", Attrs: ""},
		{Existed: false, Mode: "640", Owner: "root", Group: "root", Attrs: "i"},
	}
	for _, m := range mutations {
		if !CapturesDiffer(meta(base), meta(m)) {
			t.Fatalf("expected difference for %+v", m)
		}
	}

	a := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFileMeta, FileMeta: &base}}}
	b := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFileMeta}}}
	if !CapturesDiffer(a, b) {
		t.Fatal("nil vs non-nil FileMeta should differ")
	}
}
