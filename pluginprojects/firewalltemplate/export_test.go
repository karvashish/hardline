package main

import "testing"

func TestHardlinePluginV1(t *testing.T) {
	if HardlinePluginV1.Name != "firewall_template" {
		t.Fatalf("unexpected plugin name %q", HardlinePluginV1.Name)
	}
}
