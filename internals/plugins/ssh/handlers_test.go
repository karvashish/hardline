package ssh

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func testStep(mutate func(map[string]any)) profile.Step {
	config := map[string]any{
		"path":    "/etc/ssh/sshd_config.d/00-hardline-ssh.conf",
		"mode":    "600",
		"service": "sshd",
		"settings": map[string]any{
			"PasswordAuthentication": "no",
			"PermitRootLogin":        "no",
		},
	}
	if mutate != nil {
		mutate(config)
	}
	return profile.Step{ID: "ssh-policy", Plugin: "ssh", Config: config}
}

func TestPluginValidatesAGoodStep(t *testing.T) {
	plugin := Plugin()
	if plugin.Name != "ssh" {
		t.Fatalf("name = %q", plugin.Name)
	}
	if err := plugin.Validate(testStep(nil), nil); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestPluginEntryPointsRejectABadStep(t *testing.T) {
	plugin := Plugin()
	step := testStep(func(c map[string]any) { c["service"] = "openssh" })
	host := newHostStub()

	if err := plugin.Validate(step, nil); err == nil {
		t.Fatal("expected Validate to reject the step")
	}
	if err := plugin.Apply(pluginapi.Context{Host: host}, step); err == nil {
		t.Fatal("expected Apply to reject the step")
	}
	if _, err := plugin.Plan(pluginapi.Context{Host: host}, step); err == nil {
		t.Fatal("expected Plan to reject the step")
	}
	if _, err := plugin.Capture(pluginapi.Context{Host: host}, step); err == nil {
		t.Fatal("expected Capture to reject the step")
	}
}

func TestPluginEntryPointsRunTheStep(t *testing.T) {
	plugin := Plugin()
	host := newHostStub()
	host.effective = effectiveFor()

	if err := plugin.Apply(pluginapi.Context{Host: host}, testStep(nil)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := plugin.Plan(pluginapi.Context{Host: host}, testStep(nil)); err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if _, err := plugin.Capture(pluginapi.Context{Host: host}, testStep(nil)); err != nil {
		t.Fatalf("Capture: %v", err)
	}
}

func TestPluginRollbackDispatch(t *testing.T) {
	plugin := Plugin()
	host := newHostStub()
	snap := pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/00-hardline-ssh.conf"}

	if err := plugin.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap, Message: "sshd"}); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if err := plugin.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile}); err == nil {
		t.Fatal("expected an error for a file record with no snapshot")
	}
	if err := plugin.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap, Message: "telnetd"}); err == nil {
		t.Fatal("expected an error for an unsupported unit")
	}
	if err := plugin.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectPackage}); err == nil {
		t.Fatal("expected an error for a kind this plugin does not own")
	}
}

func TestPluginDetectConflict(t *testing.T) {
	plugin := Plugin()
	host := newHostStub()
	host.fileExists = true
	host.fileMode = "600"
	host.fileContent = "PasswordAuthentication no\n"

	snap := pluginapi.FileSnapshot{Path: "/etc/ssh/sshd_config.d/00-hardline-ssh.conf"}
	if conflicts := plugin.DetectConflict(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap}); len(conflicts) == 0 {
		t.Fatal("expected a conflict: the journal records no file but one exists")
	}
	if conflicts := plugin.DetectConflict(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectService}); conflicts != nil {
		t.Fatalf("expected no conflicts for another kind, got %v", conflicts)
	}
}

func TestValidateSpec(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(map[string]any)
		contains string
	}{
		{"valid", nil, ""},
		{"missing path", func(c map[string]any) { delete(c, "path") }, "ssh path is required"},
		{"unmanaged path", func(c map[string]any) { c["path"] = "/tmp/x.conf" }, "outside /etc managed scope"},
		{
			"path outside sshd_config.d",
			func(c map[string]any) { c["path"] = "/etc/sysctl.d/00-hardline-ssh.conf" },
			"must be under /etc/ssh/sshd_config.d/",
		},
		{"missing service", func(c map[string]any) { delete(c, "service") }, "ssh service is required"},
		{"unknown service", func(c map[string]any) { c["service"] = "openssh" }, "is not one of ssh, sshd"},
		{"missing mode", func(c map[string]any) { delete(c, "mode") }, "no file mode recorded"},
		{"bad mode", func(c map[string]any) { c["mode"] = "8888" }, "invalid file mode"},
		{"no settings", func(c map[string]any) { delete(c, "settings") }, "at least one keyword"},
		{
			"unknown keyword",
			func(c map[string]any) { c["settings"] = map[string]any{"Protocol": "2"} },
			"not one this plugin can verify",
		},
		{
			"incomplete verify context",
			func(c map[string]any) {
				c["verify_contexts"] = []any{map[string]any{"user": "admin", "host": "h"}}
			},
			"must set user, host and addr",
		},
		{
			"verify context with a separator",
			func(c map[string]any) {
				c["verify_contexts"] = []any{map[string]any{"user": "a,b", "host": "h", "addr": "10.0.0.1"}}
			},
			"cannot express",
		},
		{
			"complete verify context",
			func(c map[string]any) {
				c["verify_contexts"] = []any{map[string]any{"user": "admin", "host": "h.example", "addr": "10.0.0.1"}}
			},
			"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeSpec(testStep(tc.mutate))
			if tc.contains == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("error %q does not contain %q", err, tc.contains)
			}
		})
	}
}

func TestValidateSpecRejectsUndecodableConfig(t *testing.T) {
	step := profile.Step{ID: "ssh-policy", Plugin: "ssh", Config: map[string]any{"path": 42}}
	if _, err := decodeSpec(step); err == nil {
		t.Fatal("expected a decode error")
	}
}

func TestValidateSpecRejectsNil(t *testing.T) {
	if err := validateSpec(nil); err == nil {
		t.Fatal("expected an error for a nil spec")
	}
}
