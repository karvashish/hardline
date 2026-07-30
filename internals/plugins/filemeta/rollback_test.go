package filemeta

import (
	"errors"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestRestoreFileMeta(t *testing.T) {
	t.Run("bad path", func(t *testing.T) {
		err := restoreFileMeta(nil, pluginapi.FileMetaSnapshot{Path: "rel", Existed: true})
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("expected path error, got %v", err)
		}
	})

	t.Run("absent snapshot noop", func(t *testing.T) {
		if err := restoreFileMeta(nil, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: false}); err != nil {
			t.Fatalf("expected noop, got %v", err)
		}
	})

	t.Run("path gone", func(t *testing.T) {
		err := restoreFileMeta(&fakeHost{exists: false}, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: true})
		if err == nil || !strings.Contains(err.Error(), "no longer exists") {
			t.Fatalf("expected gone error, got %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		h := &fakeHost{exists: true}
		err := restoreFileMeta(h, pluginapi.FileMetaSnapshot{
			Path: "/etc/shadow", Existed: true, Mode: "640", Owner: "root", Group: "shadow", Attrs: "i",
		})
		if err != nil {
			t.Fatalf("restoreFileMeta failed: %v", err)
		}
		j := h.joined()
		clearIdx := strings.Index(j, "chattr -ai")
		chmodIdx := strings.Index(j, `chmod '640'`)
		if clearIdx < 0 || chmodIdx < 0 || clearIdx > chmodIdx {
			t.Fatalf("expected clear before chmod, got %#v", h.cmds)
		}
		if !strings.Contains(j, `chown 'root:shadow'`) || !strings.Contains(j, "chattr +i") {
			t.Fatalf("expected chown and attr restore, got %#v", h.cmds)
		}
	})

	t.Run("chmod error", func(t *testing.T) {
		h := &fakeHost{exists: true, runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chmod") {
				return errors.New("boom")
			}
			return nil
		}}
		err := restoreFileMeta(h, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: true, Mode: "640"})
		if err == nil || !strings.Contains(err.Error(), "restore mode") {
			t.Fatalf("expected chmod error, got %v", err)
		}
	})

	t.Run("chown error", func(t *testing.T) {
		h := &fakeHost{exists: true, runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chown") {
				return errors.New("boom")
			}
			return nil
		}}
		err := restoreFileMeta(h, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: true, Owner: "root", Group: "root"})
		if err == nil || !strings.Contains(err.Error(), "restore owner/group") {
			t.Fatalf("expected chown error, got %v", err)
		}
	})

	t.Run("attr clear error", func(t *testing.T) {
		h := &fakeHost{exists: true, runRootFn: func(cmd string) error {
			if strings.Contains(cmd, "chattr") {
				return errors.New("boom")
			}
			return nil
		}}
		err := restoreFileMeta(h, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: true, Mode: "640"})
		if err == nil || !strings.Contains(err.Error(), "attrs") {
			t.Fatalf("expected attr error, got %v", err)
		}
	})
}

func TestFileMetaConflict(t *testing.T) {
	after := pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: true, Mode: "640", Owner: "root", Group: "shadow", Attrs: "i"}

	t.Run("no conflict", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "640 root shadow", lsattr: "----i------- /etc/shadow"}
		if got := fileMetaConflict(h, after); len(got) != 0 {
			t.Fatalf("expected no conflict, got %#v", got)
		}
	})

	t.Run("metadata differs", func(t *testing.T) {
		h := &fakeHost{exists: true, stat: "600 root shadow", lsattr: "----i------- /etc/shadow"}
		got := fileMetaConflict(h, after)
		if len(got) != 1 || !strings.Contains(got[0], "metadata") {
			t.Fatalf("expected metadata conflict, got %#v", got)
		}
	})

	t.Run("now absent", func(t *testing.T) {
		got := fileMetaConflict(&fakeHost{exists: false}, after)
		if len(got) != 1 || !strings.Contains(got[0], "now absent") {
			t.Fatalf("expected absent conflict, got %#v", got)
		}
	})

	t.Run("read error", func(t *testing.T) {
		h := &fakeHost{exists: true, statErr: errors.New("boom")}
		got := fileMetaConflict(h, after)
		if len(got) != 1 || !strings.Contains(got[0], "cannot be read") {
			t.Fatalf("expected read conflict, got %#v", got)
		}
	})

	t.Run("after absent skipped", func(t *testing.T) {
		if got := fileMetaConflict(&fakeHost{}, pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: false}); len(got) != 0 {
			t.Fatalf("expected absent-after skipped, got %#v", got)
		}
	})
}

func TestPluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(&fakeHost{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFileMeta})
		if err == nil || !strings.Contains(err.Error(), "missing file metadata snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := plugin.Rollback(&fakeHost{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := plugin.Rollback(&fakeHost{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})

	t.Run("file_meta rolled back", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFileMeta, FileMeta: &pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: false}}
		if err := plugin.Rollback(&fakeHost{}, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFileMeta, FileMeta: &pluginapi.FileMetaSnapshot{Path: "/etc/shadow", Existed: false}}
		if got := plugin.DetectConflict(&fakeHost{}, obj); got != nil {
			t.Fatalf("expected no conflict for absent-after, got %v", got)
		}
		if got := plugin.DetectConflict(&fakeHost{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); got != nil {
			t.Fatalf("expected nil for non-file_meta kind, got %v", got)
		}
	})
}
