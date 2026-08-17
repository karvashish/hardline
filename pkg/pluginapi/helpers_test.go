package pluginapi

import (
	"encoding/base64"
	"errors"
	"fmt"
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
		snap, err := SnapshotRemoteFile(statStub("", nil, nil), managedTestPath)
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if snap.Existed {
			t.Fatalf("expected Existed=false, got %+v", snap)
		}
	})

	t.Run("existing file", func(t *testing.T) {
		snap, err := SnapshotRemoteFile(statStub("regular file|644|root|shadow|3\n",
			func(string) (string, error) { return "abc", nil }, nil), managedTestPath)
		if err != nil {
			t.Fatalf("SnapshotRemoteFile failed: %v", err)
		}
		if !snap.Existed || snap.Mode != "644" || snap.ContentB64 != "YWJj" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
		if snap.Owner != "root" || snap.Group != "shadow" {
			t.Fatalf("expected ownership to be captured, got %+v", snap)
		}
	})

	t.Run("stat error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(pluginAPIHostStub{
			runRootWithOutput: func(string) (string, error) { return "", errors.New("stat boom") },
		}, managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "stat boom") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("unparseable stat output", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub("644", nil, nil), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "unexpected format") {
			t.Fatalf("expected stat parse error, got %v", err)
		}
	})

	t.Run("read error", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub("regular file|644|root|root|3",
			func(string) (string, error) { return "", errors.New("read boom") }, nil), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "read boom") {
			t.Fatalf("expected read error, got %v", err)
		}
	})

	t.Run("refuses non-regular files", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub("character special file|666|root|root|0", nil, nil), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("expected non-regular file refusal, got %v", err)
		}
	})

	t.Run("refuses symlinks", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub("regular file|644|root|root|3", nil,
			func(cmd string) error {
				if strings.Contains(cmd, "test ! -L") {
					return errors.New("is a symlink")
				}
				return nil
			}), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("expected symlink refusal, got %v", err)
		}
	})

	t.Run("refuses oversized files", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub(
			fmt.Sprintf("regular file|644|root|root|%d", MaxSnapshotBytes+1), nil, nil), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("expected size refusal, got %v", err)
		}
	})

	t.Run("refuses a file that grows between stat and read", func(t *testing.T) {
		_, err := SnapshotRemoteFile(statStub("regular file|644|root|root|3",
			func(string) (string, error) { return strings.Repeat("x", MaxSnapshotBytes+1), nil }, nil), managedTestPath)
		if err == nil || !strings.Contains(err.Error(), "exceeds the") {
			t.Fatalf("expected size refusal on read, got %v", err)
		}
	})
}

func statStub(statLine string, read func(string) (string, error), run func(string) error) pluginAPIHostStub {
	return pluginAPIHostStub{
		runRoot:           run,
		runRootWithOutput: func(string) (string, error) { return statLine, nil },
		readRootFile:      read,
	}
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

	runtime := func(state string) CaptureResult {
		return CaptureResult{Objects: []ObjectRecord{{Kind: ObjectRuntimePolicy, RuntimePolicy: &RuntimePolicy{Name: "sshd -T", State: state}}}}
	}
	if CapturesDiffer(runtime("PasswordAuthentication=no"), runtime("PasswordAuthentication=no")) {
		t.Fatal("identical runtime policies should not differ")
	}
	if !CapturesDiffer(runtime("PasswordAuthentication=yes"), runtime("PasswordAuthentication=no")) {
		t.Fatal("a reloaded daemon policy should differ")
	}
	if !CapturesDiffer(runtime("x"), CaptureResult{Objects: []ObjectRecord{{Kind: ObjectRuntimePolicy}}}) {
		t.Fatal("a missing runtime policy should differ")
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
			Owner:      "root",
			Group:      "root",
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
		}, FileSnapshot{Path: managedTestPath, Existed: true, Mode: "640", Owner: "root", Group: "root", ContentB64: "!!!not-base64!!!"})
		if err == nil || !strings.Contains(err.Error(), "decode snapshot content") {
			t.Fatalf("expected decode error, got %v", err)
		}
	})
}

func TestFileSnapshotConflict(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("expected"))
	recorded := FileSnapshot{Path: managedTestPath, Existed: true, Mode: "600", Owner: "root", Group: "root", ContentB64: encoded}
	live := func(mode, owner, group, content string) pluginAPIHostStub {
		return statStub(fmt.Sprintf("regular file|%s|%s|%s|%d", mode, owner, group, len(content)),
			func(string) (string, error) { return content, nil }, nil)
	}

	if c := FileSnapshotConflict(live("600", "root", "root", "expected"), recorded); c != nil {
		t.Fatalf("matching state should report no conflict, got %v", c)
	}

	appeared := FileSnapshotConflict(live("644", "root", "root", "new"), FileSnapshot{Path: managedTestPath, Existed: false})
	if len(appeared) != 1 || !strings.Contains(appeared[0], "created since apply") {
		t.Fatalf("expected an appeared-file conflict, got %v", appeared)
	}

	if c := FileSnapshotConflict(statStub("", nil, nil), FileSnapshot{Path: managedTestPath, Existed: false}); c != nil {
		t.Fatalf("still-absent file should report no conflict, got %v", c)
	}

	removed := FileSnapshotConflict(statStub("", nil, nil), recorded)
	if len(removed) != 1 || !strings.Contains(removed[0], "now absent") {
		t.Fatalf("expected a removed-file conflict, got %v", removed)
	}

	unreadable := FileSnapshotConflict(pluginAPIHostStub{
		runRootWithOutput: func(string) (string, error) { return "", errors.New("nope") },
	}, recorded)
	if len(unreadable) != 1 || !strings.Contains(unreadable[0], "cannot be inspected") {
		t.Fatalf("expected an inspection conflict, got %v", unreadable)
	}

	drift := FileSnapshotConflict(live("600", "root", "root", "tampered"), recorded)
	if len(drift) != 1 || !strings.Contains(drift[0], "differs") {
		t.Fatalf("expected drift conflict, got %v", drift)
	}

	modeDrift := FileSnapshotConflict(live("666", "root", "root", "expected"), recorded)
	if len(modeDrift) != 1 || !strings.Contains(modeDrift[0], "mode is 666") {
		t.Fatalf("expected mode drift conflict, got %v", modeDrift)
	}

	ownerDrift := FileSnapshotConflict(live("600", "nobody", "nogroup", "expected"), recorded)
	if len(ownerDrift) != 1 || !strings.Contains(ownerDrift[0], "owner is nobody:nogroup") {
		t.Fatalf("expected owner drift conflict, got %v", ownerDrift)
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

func TestCapturesDiffer_ModeOnlyChange(t *testing.T) {
	before := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFile,
		File: &FileSnapshot{Existed: true, Mode: "666", Owner: "root", Group: "root", ContentB64: "eA=="}}}}
	after := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFile,
		File: &FileSnapshot{Existed: true, Mode: "600", Owner: "root", Group: "root", ContentB64: "eA=="}}}}

	if !CapturesDiffer(before, after) {
		t.Fatal("a mode-only change is a change")
	}

	ownerAfter := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectFile,
		File: &FileSnapshot{Existed: true, Mode: "666", Owner: "nobody", Group: "root", ContentB64: "eA=="}}}}
	if !CapturesDiffer(before, ownerAfter) {
		t.Fatal("an ownership-only change is a change")
	}

	if CapturesDiffer(before, before) {
		t.Fatal("identical file state must not report a change")
	}
}

func TestCapturesDiffer_PackageUpgrade(t *testing.T) {
	before := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectPackage,
		Package: &PackageState{Name: "curl", WasInstalled: true, Version: "8.5.0-1", PinSpec: "curl=8.5.0-1"}}}}
	after := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectPackage,
		Package: &PackageState{Name: "curl", WasInstalled: true, Version: "8.5.0-2", PinSpec: "curl=8.5.0-2"}}}}

	if !CapturesDiffer(before, after) {
		t.Fatal("a package version change is a change")
	}
	if CapturesDiffer(before, before) {
		t.Fatal("identical package state must not report a change")
	}
}

func TestCapturesDiffer_ExactServiceState(t *testing.T) {
	masked := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectService,
		Service: &ServiceState{Unit: "telnet.socket", Known: true, EnabledState: "masked", ActiveState: "inactive"}}}}
	disabled := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectService,
		Service: &ServiceState{Unit: "telnet.socket", Known: true, EnabledState: "disabled", ActiveState: "inactive"}}}}

	if !CapturesDiffer(masked, disabled) {
		t.Fatal("masked and disabled are different unit states")
	}
	if CapturesDiffer(masked, masked) {
		t.Fatal("identical service state must not report a change")
	}
}

func TestCapturesDiffer_ConfigLine(t *testing.T) {
	absent := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectConfigLine,
		ConfigLine: &ConfigLineSnapshot{Path: "/etc/nftables.conf", Line: `include "/etc/nftables.d/99-hardline.nft"`, FileExisted: true, Added: true}}}}
	present := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectConfigLine,
		ConfigLine: &ConfigLineSnapshot{Path: "/etc/nftables.conf", Line: `include "/etc/nftables.d/99-hardline.nft"`, FileExisted: true, Added: false}}}}

	if !CapturesDiffer(absent, present) {
		t.Fatal("appending the include line is a change")
	}
	if CapturesDiffer(present, present) {
		t.Fatal("identical config-line state must not report a change")
	}

	missing := CaptureResult{Objects: []ObjectRecord{{Kind: ObjectConfigLine}}}
	if !CapturesDiffer(missing, present) {
		t.Fatal("a record that lost its payload is not the same as one that kept it")
	}
	if CapturesDiffer(missing, missing) {
		t.Fatal("two empty config-line records are the same")
	}
}

func TestRestoreFileSnapshot_RestoresOwnership(t *testing.T) {
	var cmds []string
	host := pluginAPIHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
	}

	err := RestoreFileSnapshot(host, FileSnapshot{
		Path: managedTestPath, Existed: true, Mode: "640",
		Owner: "root", Group: "shadow", ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("RestoreFileSnapshot failed: %v", err)
	}

	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "chown 'root:shadow'") {
		t.Fatalf("expected ownership to be restored, got %v", cmds)
	}
}

func TestRestoreFileSnapshot_RejectsUnrecordedOwnership(t *testing.T) {
	err := RestoreFileSnapshot(pluginAPIHostStub{
		runRoot: func(string) error { return nil },
	}, FileSnapshot{
		Path: managedTestPath, Existed: true, Mode: "640",
		ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil || !strings.Contains(err.Error(), "no owner or group") {
		t.Fatalf("expected an ownership-free snapshot to be refused, got %v", err)
	}
}

func TestParseFileMode(t *testing.T) {
	rejects := map[string]string{
		"empty":        "",
		"blank":        "   ",
		"not octal":    "wide-open",
		"decimal only": "9999",
		"out of range": "77777",
	}
	for name, raw := range rejects {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFileMode(raw); err == nil {
				t.Fatalf("expected %q to be rejected", raw)
			}
		})
	}

	got, err := ParseFileMode(" 640 ")
	if err != nil || got != os.FileMode(0o640) {
		t.Fatalf("expected 0640, got %o err=%v", got, err)
	}
	if got, err := ParseFileMode("4755"); err != nil || got != os.FileMode(0o4755) {
		t.Fatalf("expected setuid bits to survive, got %o err=%v", got, err)
	}
}

func TestFormatFileMode(t *testing.T) {
	for raw, want := range map[string]string{"640": "640", "0640": "640", "2640": "2640", "4755": "4755"} {
		mode, err := ParseFileMode(raw)
		if err != nil {
			t.Fatalf("ParseFileMode(%q): %v", raw, err)
		}
		if got := FormatFileMode(mode); got != want {
			t.Fatalf("FormatFileMode(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestRestoreFileSnapshot_KeepsTheSetgidBit(t *testing.T) {
	var cmds []string
	var wroteMode os.FileMode
	host := pluginAPIHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
		writeRootFile: func(_ string, _ []byte, mode os.FileMode) error {
			wroteMode = mode
			return nil
		},
	}

	err := RestoreFileSnapshot(host, FileSnapshot{
		Path: managedTestPath, Existed: true, Mode: "2640",
		Owner: "root", Group: "shadow", ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("RestoreFileSnapshot failed: %v", err)
	}
	if wroteMode != os.FileMode(0o2640) {
		t.Fatalf("expected the recorded mode to reach the write, got %o", wroteMode)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "chmod '2640'") {
		t.Fatalf("expected the mode to be reapplied after chown clears it, got %v", cmds)
	}
}

func TestRestoreFileSnapshot_LeavesPlainModesToTheWrite(t *testing.T) {
	var cmds []string
	host := pluginAPIHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
	}

	err := RestoreFileSnapshot(host, FileSnapshot{
		Path: managedTestPath, Existed: true, Mode: "640",
		Owner: "root", Group: "root", ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err != nil {
		t.Fatalf("RestoreFileSnapshot failed: %v", err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "chmod ") {
		t.Fatalf("a plain mode needs no second chmod, got %v", cmds)
	}
}

func TestFirstLines(t *testing.T) {
	if got := FirstLines("  \n ", 3); got != "" {
		t.Fatalf("expected empty output to stay empty, got %q", got)
	}
	if got := FirstLines("a\nb\nc\nd\n", 2); got != "a; b" {
		t.Fatalf("unexpected trim: %q", got)
	}
	if got := FirstLines("only", 5); got != "only" {
		t.Fatalf("unexpected single line: %q", got)
	}
}

func TestRestoreFileSnapshot_RejectsUnrecordedMode(t *testing.T) {
	err := RestoreFileSnapshot(pluginAPIHostStub{
		runRoot: func(string) error { return nil },
	}, FileSnapshot{
		Path: managedTestPath, Existed: true, Owner: "root", Group: "root",
		ContentB64: base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if err == nil || !strings.Contains(err.Error(), "no file mode recorded") {
		t.Fatalf("expected a mode-free snapshot to be refused, got %v", err)
	}
}
