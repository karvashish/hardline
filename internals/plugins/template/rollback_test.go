package template

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestTemplatePluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()
	const managed = "/etc/ssh/sshd_config.d/99-hardline-ssh.conf"

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(templateRuntimeHelperStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile})
		if err == nil || !strings.Contains(err.Error(), "missing file snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := plugin.Rollback(templateRuntimeHelperStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})

	t.Run("file rolled back", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: managed, Existed: false}}
		if err := plugin.Rollback(templateRuntimeHelperStub{}, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: managed, Existed: false}}
		if got := plugin.DetectConflict(templateRuntimeHelperStub{}, obj); got != nil {
			t.Fatalf("expected no conflict for deleted-file after, got %v", got)
		}
		if got := plugin.DetectConflict(templateRuntimeHelperStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); got != nil {
			t.Fatalf("expected nil for non-file kind, got %v", got)
		}
	})
}
