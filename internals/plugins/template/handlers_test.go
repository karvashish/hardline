package template

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPlugin_MetadataAndValidation(t *testing.T) {
	plugin := Plugin()

	if !plugin.InternalValidation {
		t.Fatal("expected template plugin to declare internal validation")
	}

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "tmpl",
		Plugin: "template",
		Config: map[string]any{
			"src":  "x",
			"dest": "y",
			"mode": "bad",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must be octal") {
		t.Fatalf("expected template validation error, got %v", err)
	}

	_, err = plugin.Capture(pluginapi.CaptureContext{}, profile.Step{
		ID:     "tmpl",
		Plugin: "template",
		Config: map[string]any{
			"src":  "x",
			"dest": "y",
			"mode": "bad",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must be octal") {
		t.Fatalf("expected rollback template validation error, got %v", err)
	}
}

func TestPlugin_ApplyUsesValidationFlow(t *testing.T) {
	plugin := Plugin()

	err := plugin.Apply(pluginapi.ApplyContext{}, profile.Step{
		ID:     "tmpl",
		Plugin: "template",
		Config: map[string]any{
			"src":  "x",
			"dest": "y",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "profile context is required") {
		t.Fatalf("expected template apply to reach execution path, got %v", err)
	}
}

func TestPlugin_PlanAndRollback(t *testing.T) {
	plugin := Plugin()

	prof := mustLoadProfileForTemplateTests(t, map[string]string{"templates/t.tmpl": "hello"})
	step := profile.Step{
		ID:     "tmpl",
		Plugin: "template",
		Config: map[string]any{
			"src":  "templates/t.tmpl",
			"dest": "/etc/ssh/sshd_config.d/99-hardline-test.conf",
			"mode": "0644",
		},
	}

	if _, err := plugin.Plan(pluginapi.PlanContext{
		Profile: prof,
		Host:    templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 5}, readContent: "hello"},
	}, step); err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	if _, err := plugin.Capture(pluginapi.CaptureContext{Host: templateRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 5}, readContent: "hello"}}, step); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestValidateTemplateSpec(t *testing.T) {
	if err := validateTemplateSpec(nil); err == nil || !strings.Contains(err.Error(), "config is required") {
		t.Fatalf("expected nil config validation error, got %v", err)
	}
	if err := validateTemplateSpec(&Spec{Dest: "/tmp/x"}); err == nil || !strings.Contains(err.Error(), "src is required") {
		t.Fatalf("expected src validation error, got %v", err)
	}
	if err := validateTemplateSpec(&Spec{Src: "x"}); err == nil || !strings.Contains(err.Error(), "dest is required") {
		t.Fatalf("expected dest validation error, got %v", err)
	}
}
