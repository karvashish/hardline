package firewall

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestFirewallPluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()
	const managed = "/etc/nftables.d/99-hardline-firewall.nft"

	t.Run("missing payload", func(t *testing.T) {
		err := plugin.Rollback(firewallHelperRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile})
		if err == nil || !strings.Contains(err.Error(), "missing file snapshot") {
			t.Fatalf("expected missing snapshot error, got %v", err)
		}
	})

	t.Run("validate noop", func(t *testing.T) {
		if err := plugin.Rollback(firewallHelperRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectValidate}); err != nil {
			t.Fatalf("expected validate noop, got %v", err)
		}
	})

	t.Run("unsupported kind", func(t *testing.T) {
		err := plugin.Rollback(firewallHelperRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService})
		if err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
			t.Fatalf("expected unsupported kind error, got %v", err)
		}
	})

	t.Run("file rolled back", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{
			Kind:    pluginapi.ObjectFile,
			File:    &pluginapi.FileSnapshot{Path: managed, Existed: false},
			Message: MainConfigDebian,
		}
		if err := plugin.Rollback(firewallHelperRuntimeStub{}, obj); err != nil {
			t.Fatalf("Rollback failed: %v", err)
		}
	})

	// The main config the kernel is reloaded from comes off the journal, which
	// is input rather than authority, so a record naming anything outside the
	// supported set stops the rollback instead of reaching nft.
	t.Run("file record without a usable main config", func(t *testing.T) {
		for _, main := range []string{"", "/etc/evil.conf"} {
			obj := pluginapi.ObjectRecord{
				Kind:    pluginapi.ObjectFile,
				File:    &pluginapi.FileSnapshot{Path: managed, Existed: false},
				Message: main,
			}
			err := plugin.Rollback(firewallHelperRuntimeStub{}, obj)
			if err == nil || !strings.Contains(err.Error(), "unsupported main config path") {
				t.Fatalf("expected main config %q to be refused, got %v", main, err)
			}
		}
	})

	t.Run("detect conflict dispatch", func(t *testing.T) {
		obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: managed, Existed: false}}
		if got := plugin.DetectConflict(firewallHelperRuntimeStub{}, obj); got != nil {
			t.Fatalf("expected no conflict for deleted-file after, got %v", got)
		}
		if got := plugin.DetectConflict(firewallHelperRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); got != nil {
			t.Fatalf("expected nil for non-file kind, got %v", got)
		}
	})
}
