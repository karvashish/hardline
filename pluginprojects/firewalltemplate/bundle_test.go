package main

import "testing"

func TestHardlinePluginV1(t *testing.T) {
	if HardlinePluginV1.Name != "firewall_template" {
		t.Fatalf("unexpected bundle name %q", HardlinePluginV1.Name)
	}
	if len(HardlinePluginV1.Plugins) != 1 {
		t.Fatalf("expected one plugin in bundle, got %d", len(HardlinePluginV1.Plugins))
	}

	plugin := HardlinePluginV1.Plugins[0]
	if plugin.Name != "firewall_template" {
		t.Fatalf("unexpected plugin name %q", plugin.Name)
	}
	if !plugin.InternalValidation {
		t.Fatal("expected firewall_template plugin to declare internal validation")
	}
}
