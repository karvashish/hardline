package filemeta

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeMode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"0640", "640"},
		{"640", "640"},
		{" 0644 ", "644"},
		{"1777", "1777"},
	}
	for _, tc := range cases {
		got, err := normalizeMode(tc.in)
		if err != nil {
			t.Fatalf("normalizeMode(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("normalizeMode(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	if _, err := normalizeMode("nope"); err == nil || !strings.Contains(err.Error(), "invalid octal mode") {
		t.Fatalf("expected invalid mode error, got %v", err)
	}
}

func TestSnapshotFileMeta(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		if _, err := snapshotFileMeta(nil, "/etc/shadow"); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected host-required error, got %v", err)
		}
	})

	t.Run("missing path", func(t *testing.T) {
		snap, err := snapshotFileMeta(&fakeHost{exists: false}, "/etc/shadow")
		if err != nil {
			t.Fatalf("snapshotFileMeta failed: %v", err)
		}
		if snap.Existed {
			t.Fatalf("expected Existed=false, got %+v", snap)
		}
	})

	t.Run("existing with attrs", func(t *testing.T) {
		snap, err := snapshotFileMeta(&fakeHost{exists: true, stat: "640 root shadow\n", lsattr: "----i---------e------- /etc/shadow\n"}, "/etc/shadow")
		if err != nil {
			t.Fatalf("snapshotFileMeta failed: %v", err)
		}
		if !snap.Existed || snap.Mode != "640" || snap.Owner != "root" || snap.Group != "shadow" || snap.Attrs != "i" {
			t.Fatalf("unexpected snapshot: %+v", snap)
		}
	})

	t.Run("no managed attrs", func(t *testing.T) {
		snap, err := snapshotFileMeta(&fakeHost{exists: true, stat: "644 root root", lsattr: "-------------------- /etc/hosts"}, "/etc/hosts")
		if err != nil {
			t.Fatalf("snapshotFileMeta failed: %v", err)
		}
		if snap.Attrs != "" {
			t.Fatalf("expected empty attrs, got %q", snap.Attrs)
		}
	})

	t.Run("stat error", func(t *testing.T) {
		_, err := snapshotFileMeta(&fakeHost{exists: true, statErr: errors.New("stat boom")}, "/etc/shadow")
		if err == nil || !strings.Contains(err.Error(), "stat boom") {
			t.Fatalf("expected stat error, got %v", err)
		}
	})

	t.Run("bad stat format", func(t *testing.T) {
		_, err := snapshotFileMeta(&fakeHost{exists: true, stat: "640 root"}, "/etc/shadow")
		if err == nil || !strings.Contains(err.Error(), "unexpected format") {
			t.Fatalf("expected format error, got %v", err)
		}
	})

	t.Run("lsattr error", func(t *testing.T) {
		_, err := snapshotFileMeta(&fakeHost{exists: true, stat: "640 root shadow", lsattrErr: errors.New("lsattr boom")}, "/etc/shadow")
		if err == nil || !strings.Contains(err.Error(), "lsattr boom") {
			t.Fatalf("expected lsattr error, got %v", err)
		}
	})
}

func TestEnforceAbsCleanPath(t *testing.T) {
	// Absolute, canonical, printable-ASCII paths pass; trailing slashes are
	// canonicalized away.
	pass := map[string]string{
		"/etc/shadow":                    "/etc/shadow",
		"/a":                             "/a",
		"/etc/cron.d":                    "/etc/cron.d",
		"/etc/cron.d/":                   "/etc/cron.d",
		"/etc/cron.d///":                 "/etc/cron.d",
		"/boot/grub/grub.cfg":            "/boot/grub/grub.cfg",
		"/etc/foo.bar-baz_qux@x":         "/etc/foo.bar-baz_qux@x",
		"/etc/apt/sources.list.d/x.list": "/etc/apt/sources.list.d/x.list",
		"/a/b/c/d/e/f/g":                 "/a/b/c/d/e/f/g",
		"/root/.ssh":                     "/root/.ssh",
	}
	for in, want := range pass {
		got, err := enforceAbsCleanPath(in)
		if err != nil {
			t.Fatalf("expected %q to pass, got error: %v", in, err)
		}
		if got != want {
			t.Fatalf("enforceAbsCleanPath(%q) = %q, want %q", in, got, want)
		}
	}

	// Everything else hard-fails. Key = input, value = expected error substring.
	fail := map[string]string{
		// empty / whitespace-only
		"":    "empty",
		" ":   "allowed set",
		"   ": "allowed set",
		"\t":  "allowed set",
		"\n":  "allowed set",
		// relative / non-absolute
		"etc/shadow": "absolute",
		"x":          "absolute",
		"a/b":        "absolute",
		"./etc":      "absolute",
		"../etc":     "absolute",
		".":          "absolute",
		"..":         "absolute",
		"~/x":        "allowed set",
		// leading whitespace (rejected by the charset before the absolute check)
		" /etc/shadow":  "allowed set",
		"\t/etc/shadow": "allowed set",
		// trailing / embedded whitespace
		"/etc/shadow ": "allowed set",
		"/etc/sh adow": "allowed set",
		// control characters, NUL, newline, CR, DEL
		"/etc/sh\nadow":   "allowed set",
		"/etc/sh\tadow":   "allowed set",
		"/etc/sh\radow":   "allowed set",
		"/etc/sh\x00adow": "allowed set",
		"/etc/\x7f":       "allowed set",
		// non-ASCII / unicode homoglyph
		"/etc/café":       "allowed set",
		"/etc/sh\xffadow": "allowed set",
		// shell metacharacters: these reach a root sh -lc
		"/etc/99-hardline$(id).conf": "allowed set",
		"/etc/99-hardline`id`.conf":  "allowed set",
		"/etc/99-hardline${x}.conf":  "allowed set",
		"/etc/shadow;id":             "allowed set",
		"/etc/shadow|id":             "allowed set",
		"/etc/shadow&":               "allowed set",
		"/etc/shadow>x":              "allowed set",
		"/etc/'shadow'":              "allowed set",
		"/etc/\"shadow\"":            "allowed set",
		"/etc/shadow\\x":             "allowed set",
		"/etc/*":                     "allowed set",
		"/etc/foo.bar-baz_qux+v=1@x": "allowed set",
		// path traversal
		"/etc/../shadow": "normalized",
		"/a/b/../c":      "normalized",
		"/..":            "normalized",
		"/../../etc":     "normalized",
		"/etc/foo/..":    "normalized",
		// redundant separators / dot segments
		"/etc//shadow":  "normalized",
		"/etc/./shadow": "normalized",
		"/etc/foo/.":    "normalized",
		// filesystem root and slash-only variants
		"/":   "filesystem root",
		"//":  "filesystem root",
		"///": "filesystem root",
	}
	for in, wantErr := range fail {
		got, err := enforceAbsCleanPath(in)
		if err == nil {
			t.Fatalf("expected %q to hard-fail, but it passed as %q", in, got)
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("enforceAbsCleanPath(%q) error = %q, want substring %q", in, err.Error(), wantErr)
		}
	}
}

func TestApplyManagedAttrs(t *testing.T) {
	t.Run("set immutable clears append", func(t *testing.T) {
		var cmds []string
		err := applyManagedAttrs(func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}, "/etc/shadow", "i")
		if err != nil {
			t.Fatalf("applyManagedAttrs failed: %v", err)
		}
		if len(cmds) != 2 || !strings.Contains(cmds[0], "chattr -a") || !strings.Contains(cmds[1], "chattr +i") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("clear all", func(t *testing.T) {
		var cmds []string
		if err := applyManagedAttrs(func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}, "/etc/shadow", ""); err != nil {
			t.Fatalf("applyManagedAttrs failed: %v", err)
		}
		if len(cmds) != 1 || !strings.Contains(cmds[0], "chattr -ai") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("set both", func(t *testing.T) {
		var cmds []string
		if err := applyManagedAttrs(func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}, "/etc/shadow", "ai"); err != nil {
			t.Fatalf("applyManagedAttrs failed: %v", err)
		}
		if len(cmds) != 1 || !strings.Contains(cmds[0], "chattr +ai") {
			t.Fatalf("unexpected commands: %#v", cmds)
		}
	})

	t.Run("clear error", func(t *testing.T) {
		err := applyManagedAttrs(func(string) error { return errors.New("boom") }, "/etc/shadow", "i")
		if err == nil || !strings.Contains(err.Error(), "clear attrs") {
			t.Fatalf("expected clear error, got %v", err)
		}
	})

	t.Run("set error", func(t *testing.T) {
		err := applyManagedAttrs(func(cmd string) error {
			if strings.Contains(cmd, "+") {
				return errors.New("boom")
			}
			return nil
		}, "/etc/shadow", "i")
		if err == nil || !strings.Contains(err.Error(), "set attrs") {
			t.Fatalf("expected set error, got %v", err)
		}
	})
}
