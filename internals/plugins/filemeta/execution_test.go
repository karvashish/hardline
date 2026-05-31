package filemeta

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

type fakeHost struct {
	exists    bool
	stat      string
	statErr   error
	lsattr    string
	lsattrErr error
	runRootFn func(string) error
	cmds      []string
}

func (h *fakeHost) RunRoot(cmd string) error {
	h.cmds = append(h.cmds, cmd)
	if strings.HasPrefix(strings.TrimSpace(cmd), "test -e") {
		if h.exists {
			return nil
		}
		return errors.New("absent")
	}
	if h.runRootFn != nil {
		return h.runRootFn(cmd)
	}
	return nil
}

func (h *fakeHost) RunRootWithOutput(cmd string) (string, error) {
	h.cmds = append(h.cmds, cmd)
	if strings.Contains(cmd, "stat -c") {
		return h.stat, h.statErr
	}
	if strings.Contains(cmd, "lsattr") {
		return h.lsattr, h.lsattrErr
	}
	return "", nil
}

func (h *fakeHost) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return h.RunRootWithOutput(cmd)
}
func (*fakeHost) Stat(string) (os.FileInfo, error)                { return nil, errors.New("not implemented") }
func (*fakeHost) ReadRootFile(string) (string, error)             { return "", nil }
func (*fakeHost) WriteRootFile(string, []byte, os.FileMode) error { return nil }

var _ pluginapi.Host = (*fakeHost)(nil)

func boolPtr(b bool) *bool { return &b }

func (h *fakeHost) joined() string { return strings.Join(h.cmds, "\n") }

func TestApply(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		err := Apply(pluginapi.Context{}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err == nil || !strings.Contains(err.Error(), "host context is required") {
			t.Fatalf("expected host error, got %v", err)
		}
	})

	t.Run("bad path", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: &fakeHost{}}, &Spec{Path: "rel", Mode: "0600"})
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("expected path error, got %v", err)
		}
	})

	t.Run("absent target", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: &fakeHost{exists: false}}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err == nil || !strings.Contains(err.Error(), "does not exist") {
			t.Fatalf("expected absent error, got %v", err)
		}
	})

	t.Run("snapshot error", func(t *testing.T) {
		err := Apply(pluginapi.Context{Host: &fakeHost{exists: true, statErr: errors.New("stat boom")}}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err == nil || !strings.Contains(err.Error(), "stat boom") {
			t.Fatalf("expected snapshot error, got %v", err)
		}
	})

	t.Run("bad mode", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "---- /etc/shadow"}
		err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "nope"})
		if err == nil || !strings.Contains(err.Error(), "invalid octal mode") {
			t.Fatalf("expected mode error, got %v", err)
		}
	})

	t.Run("noop", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600"}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if strings.Contains(h.joined(), "chmod") || strings.Contains(h.joined(), "chown") || strings.Contains(h.joined(), "chattr") {
			t.Fatalf("expected no mutation commands, got %#v", h.cmds)
		}
	})

	t.Run("mode change", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600"}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), `chmod "600"`) {
			t.Fatalf("expected chmod 600, got %#v", h.cmds)
		}
	})

	t.Run("owner and group change", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Owner: "bin", Group: "bin"}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), `chown "bin:bin"`) {
			t.Fatalf("expected chown bin:bin, got %#v", h.cmds)
		}
	})

	t.Run("owner only", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Owner: "bin"}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), `chown "bin"`) {
			t.Fatalf("expected chown bin, got %#v", h.cmds)
		}
	})

	t.Run("group only", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Group: "bin"}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), `chown ":bin"`) {
			t.Fatalf("expected chown :bin, got %#v", h.cmds)
		}
	})

	t.Run("set immutable", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Immutable: boolPtr(true)}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), "chattr +i") || strings.Contains(h.joined(), "chmod") {
			t.Fatalf("expected chattr +i and no chmod, got %#v", h.cmds)
		}
	})

	t.Run("clear immutable", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "----i--------- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Immutable: boolPtr(false)}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !strings.Contains(h.joined(), "chattr -ai") {
			t.Fatalf("expected chattr -ai, got %#v", h.cmds)
		}
	})

	t.Run("mode change on immutable file lifts then restores", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "----i--------- /etc/shadow"}
		if err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600", Immutable: boolPtr(true)}); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		j := h.joined()
		clearIdx := strings.Index(j, "chattr -ai")
		chmodIdx := strings.Index(j, `chmod "600"`)
		setIdx := strings.LastIndex(j, "chattr +i")
		if clearIdx < 0 || chmodIdx < 0 || setIdx < 0 || !(clearIdx < chmodIdx && chmodIdx < setIdx) {
			t.Fatalf("expected clear -> chmod -> set ordering, got %#v", h.cmds)
		}
	})

	t.Run("chmod error", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "---- /etc/shadow", runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chmod") {
				return errors.New("chmod boom")
			}
			return nil
		}}
		err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err == nil || !strings.Contains(err.Error(), "chmod") {
			t.Fatalf("expected chmod error, got %v", err)
		}
	})

	t.Run("chown error", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow", runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chown") {
				return errors.New("chown boom")
			}
			return nil
		}}
		err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Owner: "bin"})
		if err == nil || !strings.Contains(err.Error(), "chown") {
			t.Fatalf("expected chown error, got %v", err)
		}
	})

	t.Run("attr error", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow", runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chattr") {
				return errors.New("chattr boom")
			}
			return nil
		}}
		err := Apply(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Immutable: boolPtr(true)})
		if err == nil || !strings.Contains(err.Error(), "attrs") {
			t.Fatalf("expected attr error, got %v", err)
		}
	})
}

func TestPlan(t *testing.T) {
	t.Run("host required", func(t *testing.T) {
		if _, err := Plan(pluginapi.Context{}, &Spec{Path: "/etc/shadow", Mode: "0600"}); err == nil {
			t.Fatal("expected host error")
		}
	})

	t.Run("bad path", func(t *testing.T) {
		if _, err := Plan(pluginapi.Context{Host: &fakeHost{}}, &Spec{Path: "rel", Mode: "0600"}); err == nil {
			t.Fatal("expected path error")
		}
	})

	t.Run("absent target", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{Host: &fakeHost{exists: false}}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange || !strings.Contains(res.Summary, "absent") || len(res.Highlights) == 0 {
			t.Fatalf("unexpected plan: %+v", res)
		}
	})

	t.Run("bad mode", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "---- /etc/shadow"}
		if _, err := Plan(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "nope"}); err == nil {
			t.Fatal("expected mode error")
		}
	})

	t.Run("no change", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root root", lsattr: "---- /etc/shadow"}
		res, err := Plan(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if res.WillChange || len(res.Diff) != 0 {
			t.Fatalf("expected no change, got %+v", res)
		}
	})

	t.Run("changes", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root root", lsattr: "---- /etc/shadow"}
		res, err := Plan(pluginapi.Context{Host: h}, &Spec{Path: "/etc/shadow", Mode: "0600", Owner: "bin", Group: "bin", Immutable: boolPtr(true)})
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if !res.WillChange || len(res.Diff) == 0 {
			t.Fatalf("expected change, got %+v", res)
		}
	})
}

func TestCapture(t *testing.T) {
	t.Run("spec nil", func(t *testing.T) {
		if _, err := Capture(pluginapi.Context{Host: &fakeHost{}}, "s", nil); err == nil {
			t.Fatal("expected spec error")
		}
	})

	t.Run("host nil", func(t *testing.T) {
		if _, err := Capture(pluginapi.Context{}, "s", &Spec{Path: "/etc/shadow"}); err == nil {
			t.Fatal("expected host error")
		}
	})

	t.Run("bad path", func(t *testing.T) {
		if _, err := Capture(pluginapi.Context{Host: &fakeHost{}}, "s", &Spec{Path: "rel"}); err == nil {
			t.Fatal("expected path error")
		}
	})

	t.Run("snapshot error", func(t *testing.T) {
		h := &fakeHost{exists: true, statErr: errors.New("stat boom")}
		if _, err := Capture(pluginapi.Context{Host: h}, "s", &Spec{Path: "/etc/shadow"}); err == nil {
			t.Fatal("expected snapshot error")
		}
	})

	t.Run("success", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root shadow", lsattr: "----i------- /etc/shadow"}
		rec, err := Capture(pluginapi.Context{Host: h}, "s", &Spec{Path: "/etc/shadow", Mode: "0600"})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != pluginapi.ModeDeterministic || len(rec.Objects) != 1 || rec.Objects[0].Kind != pluginapi.ObjectFileMeta {
			t.Fatalf("unexpected capture: %+v", rec)
		}
		if rec.Objects[0].FileMeta == nil || rec.Objects[0].FileMeta.Attrs != "i" {
			t.Fatalf("unexpected snapshot: %+v", rec.Objects[0].FileMeta)
		}
	})

	t.Run("trailing slash canonicalized", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "700 root root", lsattr: "---- /etc/cron.d"}
		rec, err := Capture(pluginapi.Context{Host: h}, "s", &Spec{Path: "/etc/cron.d/", Mode: "0700"})
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.Objects[0].FileMeta.Path != "/etc/cron.d" {
			t.Fatalf("expected canonical path /etc/cron.d, got %q", rec.Objects[0].FileMeta.Path)
		}
	})
}
