package profile

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_BasicErrors(t *testing.T) {
	if _, err := Load(""); err == nil || !strings.Contains(err.Error(), "profile not found") {
		t.Fatalf("expected empty-profile error, got %v", err)
	}

	missingDir := t.TempDir()
	if _, err := Load(missingDir); err == nil || !strings.Contains(err.Error(), "open profile.json") {
		t.Fatalf("expected missing profile.json error, got %v", err)
	}

	badDir := t.TempDir()
	writeFile(t, filepath.Join(badDir, "profile.json"), "{bad json")
	if _, err := Load(badDir); err == nil || !strings.Contains(err.Error(), "decode profile.json") {
		t.Fatalf("expected bad profile.json decode error, got %v", err)
	}
}

func TestLoad_ActionsErrors(t *testing.T) {
	t.Run("missing action file", func(t *testing.T) {
		dir := t.TempDir()
		writeProfileJSON(t, dir, []string{"actions/missing.json"}, []string{})
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "open action file") {
			t.Fatalf("expected open action file error, got %v", err)
		}
	})

	t.Run("invalid action json", func(t *testing.T) {
		dir := t.TempDir()
		writeProfileJSON(t, dir, []string{"actions/a.json"}, []string{})
		writeFile(t, filepath.Join(dir, "actions", "a.json"), "{bad json")
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "decode action file") {
			t.Fatalf("expected decode action file error, got %v", err)
		}
	})

	t.Run("generic plugin config is accepted at load time", func(t *testing.T) {
		dir := t.TempDir()
		writeProfileJSON(t, dir, []string{"actions/a.json"}, []string{"templates/declared.tmpl"})
		writeFile(t, filepath.Join(dir, "actions", "a.json"), `{
  "steps": [
    {
      "id": "tmpl",
      "plugin": "template",
      "config": {"src": "templates/not-declared.tmpl", "dest": "/tmp/x", "mode": "0644"}
    },
    {
      "id": "fw",
      "plugin": "firewall_template",
      "config": {"backend": "nftables", "policy": "deny", "template_src": "templates/not-declared.tmpl", "template_dest": "/etc/nftables.conf", "allow": []}
    }
  ]
}`)
		if _, err := Load(dir); err != nil {
			t.Fatalf("expected generic action load success, got %v", err)
		}
	})
}

func TestLoad_AndTemplateHelpers_SuccessAndErrors(t *testing.T) {
	dir := t.TempDir()
	writeProfileJSON(t, dir, []string{"actions/a.json"}, []string{"templates/t.tmpl", "templates/missing.tmpl"})
	writeFile(t, filepath.Join(dir, "actions", "a.json"), `{
  "steps": [
    {
      "id": "tmpl",
      "plugin": "template",
      "config": {"src": "templates/t.tmpl", "dest": "/etc/example.conf", "mode": "0644"}
    }
  ]
}`)
	writeFile(t, filepath.Join(dir, "templates", "t.tmpl"), "hello")

	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(p.ActionFiles) != 1 {
		t.Fatalf("expected 1 action file, got %d", len(p.ActionFiles))
	}
	paths := p.ActionPaths()
	if len(paths) != 1 {
		t.Fatalf("expected 1 action path, got %d", len(paths))
	}
	if got, want := paths[0], filepath.Join(dir, "actions", "a.json"); got != want {
		t.Fatalf("unexpected action path: got %q want %q", got, want)
	}

	if _, err := p.LoadTemplate("templates/undeclared.tmpl"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected undeclared template error, got %v", err)
	}
	if _, err := p.LoadTemplate("templates/missing.tmpl"); err == nil || !strings.Contains(err.Error(), "read template") {
		t.Fatalf("expected missing template read error, got %v", err)
	}
	content, err := p.LoadTemplate("templates/t.tmpl")
	if err != nil {
		t.Fatalf("expected LoadTemplate success, got %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected template content: %q", string(content))
	}
}

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

func writeProfileJSON(t *testing.T, dir string, actions, templates []string) {
	t.Helper()

	actionsJSON := "[]"
	if len(actions) > 0 {
		actionsJSON = `["` + strings.Join(actions, `","`) + `"]`
	}
	templatesJSON := "[]"
	if len(templates) > 0 {
		templatesJSON = `["` + strings.Join(templates, `","`) + `"]`
	}

	writeFile(t, filepath.Join(dir, "profile.json"), `{
  "id": "profile-id",
  "display_name": "Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": `+actionsJSON+`,
  "templates": `+templatesJSON+`
}`)
}
