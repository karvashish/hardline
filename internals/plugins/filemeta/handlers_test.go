package filemeta

import (
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func TestPluginMetadata(t *testing.T) {
	p := Plugin()
	if p.Name != "file_meta" {
		t.Fatalf("unexpected name %q", p.Name)
	}
	if !p.InternalValidation {
		t.Fatal("expected internal validation")
	}
}

func TestValidateSpec(t *testing.T) {
	cases := []struct {
		name    string
		spec    *Spec
		wantErr string
	}{
		{name: "nil", spec: nil, wantErr: "config is required"},
		{name: "bad path", spec: &Spec{Path: "rel", Mode: "0600"}, wantErr: "absolute"},
		{name: "bad mode", spec: &Spec{Path: "/etc/shadow", Mode: "nope"}, wantErr: "invalid octal mode"},
		{name: "no fields", spec: &Spec{Path: "/etc/shadow"}, wantErr: "at least one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSpec(tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}

	if err := validateSpec(&Spec{Path: "/etc/shadow", Mode: "0640"}); err != nil {
		t.Fatalf("expected valid spec, got %v", err)
	}
	if err := validateSpec(&Spec{Path: "/etc/shadow", Immutable: boolPtr(true)}); err != nil {
		t.Fatalf("expected valid attr-only spec, got %v", err)
	}
}

func TestPluginValidationFlow(t *testing.T) {
	p := Plugin()
	step := profile.Step{ID: "fm", Plugin: "file_meta", Config: map[string]any{"path": "/etc/shadow"}}

	if err := p.Apply(pluginapi.Context{}, step); err == nil || !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("expected apply validation error, got %v", err)
	}
	if _, err := p.Plan(pluginapi.Context{}, step); err == nil || !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("expected plan validation error, got %v", err)
	}
	if _, err := p.Capture(pluginapi.Context{}, step); err == nil || !strings.Contains(err.Error(), "at least one of") {
		t.Fatalf("expected capture validation error, got %v", err)
	}
}

func TestPluginDecodeError(t *testing.T) {
	p := Plugin()
	step := profile.Step{ID: "fm", Plugin: "file_meta", Config: map[string]any{"path": 123}}
	if err := p.Apply(pluginapi.Context{}, step); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected decode error, got %v", err)
	}
	if _, err := p.Plan(pluginapi.Context{}, step); err == nil {
		t.Fatal("expected plan decode error")
	}
	if _, err := p.Capture(pluginapi.Context{}, step); err == nil {
		t.Fatal("expected capture decode error")
	}
}
