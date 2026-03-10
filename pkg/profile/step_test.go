package profile

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestStepPluginHelpers(t *testing.T) {
	step := Step{
		Plugin: "  Template  ",
		Config: map[string]any{"src": "templates/x.tmpl"},
	}

	if got := step.PluginName(); got != "template" {
		t.Fatalf("unexpected plugin name %q", got)
	}
	if len(step.Config) != 1 {
		t.Fatalf("expected one config field, got %+v", step.Config)
	}

	empty := Step{}
	if got := empty.PluginName(); got != "" {
		t.Fatalf("expected empty plugin name, got %q", got)
	}
	if empty.Config != nil {
		t.Fatalf("expected nil config for empty step, got %+v", empty.Config)
	}
}

func TestStepDecode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		type packageStep struct {
			Update  bool     `json:"update"`
			Install []string `json:"install"`
		}

		step := Step{
			ID:     "pkg",
			Plugin: "packages",
			Config: map[string]any{
				"update":  true,
				"install": []any{"curl", "git"},
			},
		}

		var spec packageStep
		if err := step.Decode(&spec); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if !spec.Update || len(spec.Install) != 2 || spec.Install[0] != "curl" || spec.Install[1] != "git" {
			t.Fatalf("unexpected decoded spec: %+v", spec)
		}
	})

	t.Run("nil config decodes zero value", func(t *testing.T) {
		type serviceStep struct {
			Name    string `json:"name"`
			Enabled *bool  `json:"enabled"`
			State   string `json:"state"`
		}

		var spec serviceStep
		if err := (Step{ID: "svc", Plugin: "service"}).Decode(&spec); err != nil {
			t.Fatalf("Decode with nil config failed: %v", err)
		}
		if spec.Name != "" || spec.State != "" || spec.Enabled != nil {
			t.Fatalf("expected zero-value service spec, got %+v", spec)
		}
	})

	t.Run("encode error", func(t *testing.T) {
		type serviceStep struct {
			Name string `json:"name"`
		}

		err := (Step{
			ID:     "svc",
			Plugin: "service",
			Config: map[string]any{"bad": make(chan int)},
		}).Decode(&serviceStep{})
		if err == nil || !strings.Contains(err.Error(), "encode step config") {
			t.Fatalf("expected step encode error, got %v", err)
		}
	})

	t.Run("decode error", func(t *testing.T) {
		type serviceStep struct {
			Enabled *bool `json:"enabled"`
		}

		err := (Step{
			ID:     "svc",
			Plugin: "service",
			Config: map[string]any{"enabled": "yes"},
		}).Decode(&serviceStep{})
		if err == nil || !strings.Contains(err.Error(), "decode step config") {
			t.Fatalf("expected step decode error, got %v", err)
		}
	})
}

func TestLoad_MultipleActionFiles(t *testing.T) {
	dir := t.TempDir()
	writeProfileJSON(t, dir, []string{"actions/a.json", "actions/b.json"}, []string{})
	writeFile(t, filepath.Join(dir, "actions", "a.json"), `{
  "steps": [
    {"id": "pkg", "plugin": "packages", "config": {"install": ["curl"]}}
  ]
}`)
	writeFile(t, filepath.Join(dir, "actions", "b.json"), `{
  "steps": [
    {"id": "svc", "plugin": "service", "config": {"name": "ssh", "state": "started"}}
  ]
}`)

	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(p.ActionFiles) != 2 {
		t.Fatalf("expected 2 action files, got %d", len(p.ActionFiles))
	}
	if got := p.ActionFiles[0].Path; got != filepath.Join(dir, "actions", "a.json") {
		t.Fatalf("unexpected first action path %q", got)
	}
	if got := p.ActionFiles[1].Path; got != filepath.Join(dir, "actions", "b.json") {
		t.Fatalf("unexpected second action path %q", got)
	}
	if got := p.ActionFiles[0].Steps[0].PluginName(); got != "packages" {
		t.Fatalf("unexpected first action plugin %q", got)
	}
	if got := p.ActionFiles[1].Steps[0].PluginName(); got != "service" {
		t.Fatalf("unexpected second action plugin %q", got)
	}
	if got := p.ActionFiles[0].Steps[0].Config["install"]; got == nil {
		t.Fatalf("expected package config to be preserved, got %+v", p.ActionFiles[0].Steps[0].Config)
	}
}
