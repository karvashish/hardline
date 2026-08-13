package main

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

func TestPluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()
	const managed = "/etc/nftables.d/99-hardline-firewall.nft"

	if err := plugin.Rollback(fwTemplateRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); err == nil || !strings.Contains(err.Error(), "missing file snapshot") {
		t.Fatalf("expected missing snapshot error, got %v", err)
	}
	if err := plugin.Rollback(fwTemplateRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); err == nil || !strings.Contains(err.Error(), "cannot roll back kind") {
		t.Fatalf("expected unsupported kind error, got %v", err)
	}

	obj := pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &pluginapi.FileSnapshot{Path: managed, Existed: false}}
	if err := plugin.Rollback(fwTemplateRuntimeStub{}, obj); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}
	if got := plugin.DetectConflict(fwTemplateRuntimeStub{}, obj); got != nil {
		t.Fatalf("expected no conflict for deleted-file after, got %v", got)
	}
	if got := plugin.DetectConflict(fwTemplateRuntimeStub{}, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); got != nil {
		t.Fatalf("expected nil for non-file kind, got %v", got)
	}
}
