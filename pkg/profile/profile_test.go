package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFromBundle_BasicErrors(t *testing.T) {
	if _, err := LoadFromBundle("", nil); err == nil || !strings.Contains(err.Error(), "profile not found") {
		t.Fatalf("expected empty-profile error, got %v", err)
	}

	if _, err := LoadFromBundle("p", map[string][]byte{}); err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
		t.Fatalf("expected uncovered profile.json error, got %v", err)
	}

	bad := map[string][]byte{"profile.json": []byte("{bad json")}
	if _, err := LoadFromBundle("p", bad); err == nil || !strings.Contains(err.Error(), "decode profile.json") {
		t.Fatalf("expected bad profile.json decode error, got %v", err)
	}
}

func TestLoadFromBundle_ActionsErrors(t *testing.T) {
	t.Run("action file outside the signed set", func(t *testing.T) {
		files := map[string][]byte{
			"profile.json": profileJSON([]string{"actions/missing.json"}, nil),
		}
		if _, err := LoadFromBundle("p", files); err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
			t.Fatalf("expected uncovered action error, got %v", err)
		}
	})

	t.Run("invalid action json", func(t *testing.T) {
		files := map[string][]byte{
			"profile.json":   profileJSON([]string{"actions/a.json"}, nil),
			"actions/a.json": []byte("{bad json"),
		}
		if _, err := LoadFromBundle("p", files); err == nil || !strings.Contains(err.Error(), "decode action file") {
			t.Fatalf("expected decode action file error, got %v", err)
		}
	})

	t.Run("generic plugin config is accepted at load time", func(t *testing.T) {
		files := map[string][]byte{
			"profile.json": profileJSON([]string{"actions/a.json"}, []string{"templates/declared.tmpl"}),
			"actions/a.json": []byte(`{
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
}`),
		}
		if _, err := LoadFromBundle("p", files); err != nil {
			t.Fatalf("expected generic action load success, got %v", err)
		}
	})
}

func TestLoadFromBundle_AndTemplateHelpers_SuccessAndErrors(t *testing.T) {
	files := map[string][]byte{
		"profile.json": profileJSON([]string{"actions/a.json"}, []string{"templates/t.tmpl", "templates/unsigned.tmpl"}),
		"actions/a.json": []byte(`{
  "steps": [
    {
      "id": "tmpl",
      "plugin": "template",
      "config": {"src": "templates/t.tmpl", "dest": "/etc/example.conf", "mode": "0644"}
    }
  ]
}`),
		"templates/t.tmpl": []byte("hello"),
	}

	p, err := LoadFromBundle("p", files)
	if err != nil {
		t.Fatalf("LoadFromBundle failed: %v", err)
	}
	if len(p.ActionFiles) != 1 {
		t.Fatalf("expected 1 action file, got %d", len(p.ActionFiles))
	}
	paths, err := p.ActionPaths()
	if err != nil {
		t.Fatalf("ActionPaths failed: %v", err)
	}
	if len(paths) != 1 || paths[0] != "actions/a.json" {
		t.Fatalf("unexpected action paths: %+v", paths)
	}

	if _, err := p.LoadTemplate("templates/undeclared.tmpl"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("expected undeclared template error, got %v", err)
	}
	// Declared but absent from the snapshot: the profile points at content the
	// signature never covered, which must not fall back to a disk read.
	if _, err := p.LoadTemplate("templates/unsigned.tmpl"); err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
		t.Fatalf("expected uncovered template error, got %v", err)
	}
	content, err := p.LoadTemplate("templates/t.tmpl")
	if err != nil {
		t.Fatalf("expected LoadTemplate success, got %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected template content: %q", string(content))
	}
}

// TestLoadFromBundle_IgnoresDiskContent is the regression test for the
// verified-payload TOCTOU: once a bundle is loaded, rewriting the profile
// directory must not change a single byte the profile serves.
func TestLoadFromBundle_IgnoresDiskContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "templates", "t.tmpl"), []byte("attacker-controlled"), 0o644); err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"profile.json":     profileJSON(nil, []string{"templates/t.tmpl"}),
		"templates/t.tmpl": []byte("signed"),
	}
	p, err := LoadFromBundle(dir, files)
	if err != nil {
		t.Fatalf("LoadFromBundle failed: %v", err)
	}

	content, err := p.LoadTemplate("templates/t.tmpl")
	if err != nil {
		t.Fatalf("LoadTemplate failed: %v", err)
	}
	if string(content) != "signed" {
		t.Fatalf("template served disk content %q instead of the signed bytes", string(content))
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
			Plugin: "packages_apt",
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

func TestLoadFromBundle_MultipleActionFiles(t *testing.T) {
	files := map[string][]byte{
		"profile.json": profileJSON([]string{"actions/a.json", "actions/b.json"}, nil),
		"actions/a.json": []byte(`{
  "steps": [
    {"id": "pkg", "plugin": "packages_apt", "config": {"install": ["curl"]}}
  ]
}`),
		"actions/b.json": []byte(`{
  "steps": [
    {"id": "svc", "plugin": "service", "config": {"name": "ssh", "state": "started"}}
  ]
}`),
	}

	p, err := LoadFromBundle("p", files)
	if err != nil {
		t.Fatalf("LoadFromBundle failed: %v", err)
	}
	if len(p.ActionFiles) != 2 {
		t.Fatalf("expected 2 action files, got %d", len(p.ActionFiles))
	}
	if got := p.ActionFiles[0].Path; got != "actions/a.json" {
		t.Fatalf("unexpected first action path %q", got)
	}
	if got := p.ActionFiles[1].Path; got != "actions/b.json" {
		t.Fatalf("unexpected second action path %q", got)
	}
	if got := p.ActionFiles[0].Steps[0].PluginName(); got != "packages_apt" {
		t.Fatalf("unexpected first action plugin %q", got)
	}
	if got := p.ActionFiles[1].Steps[0].PluginName(); got != "service" {
		t.Fatalf("unexpected second action plugin %q", got)
	}
	if got := p.ActionFiles[0].Steps[0].Config["install"]; got == nil {
		t.Fatalf("expected package config to be preserved, got %+v", p.ActionFiles[0].Steps[0].Config)
	}
}

func TestProfileOverrides(t *testing.T) {
	p := &Profile{AllowedOverrides: []string{"ssh_port", "https_port"}}

	if err := p.ValidateOverrides(map[string]json.RawMessage{"ssh_port": json.RawMessage(`2222`)}); err != nil {
		t.Fatalf("expected declared override to validate, got %v", err)
	}
	if err := p.ValidateOverrides(map[string]json.RawMessage{"smtp_port": json.RawMessage(`25`)}); err == nil || !strings.Contains(err.Error(), "does not allow overrides") {
		t.Fatalf("expected undeclared override error, got %v", err)
	}

	p.SetRuntimeOverrides(map[string]json.RawMessage{"ssh_port": json.RawMessage(`2222`)})
	runtime := p.RuntimeOverrides()
	if string(runtime["ssh_port"]) != "2222" {
		t.Fatalf("expected runtime override to round-trip, got %+v", runtime)
	}

	delete(runtime, "ssh_port")
	if fresh := p.RuntimeOverrides(); string(fresh["ssh_port"]) != "2222" {
		t.Fatalf("expected runtime override clone, got %+v", fresh)
	}

	if got := (*Profile)(nil).RuntimeOverrides(); got != nil {
		t.Fatalf("expected nil profile to return nil overrides, got %+v", got)
	}
}

func TestValidateAllowedOverrides(t *testing.T) {
	if err := (&Profile{AllowedOverrides: []string{"ssh_port", "https_port"}}).validateAllowedOverrides(); err != nil {
		t.Fatalf("expected valid override declarations, got %v", err)
	}
	if err := (&Profile{AllowedOverrides: []string{""}}).validateAllowedOverrides(); err == nil || !strings.Contains(err.Error(), "empty name") {
		t.Fatalf("expected empty-name error, got %v", err)
	}
	if err := (&Profile{AllowedOverrides: []string{"SSH_PORT"}}).validateAllowedOverrides(); err == nil || !strings.Contains(err.Error(), "invalid name") {
		t.Fatalf("expected invalid-name error, got %v", err)
	}
	if err := (&Profile{AllowedOverrides: []string{"ssh_port", "ssh_port"}}).validateAllowedOverrides(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate override error, got %v", err)
	}
}

func profileJSON(actions, templates []string) []byte {
	actionsJSON := "[]"
	if len(actions) > 0 {
		actionsJSON = `["` + strings.Join(actions, `","`) + `"]`
	}
	templatesJSON := "[]"
	if len(templates) > 0 {
		templatesJSON = `["` + strings.Join(templates, `","`) + `"]`
	}

	return []byte(`{
  "id": "profile-id",
  "display_name": "Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ` + actionsJSON + `,
  "templates": ` + templatesJSON + `,
  "allowed_overrides": []
}`)
}

// TestResolveRejectsEscapes covers references whose shape reaches outside the
// signed tree. A reference that is merely absent from the snapshot is rejected
// one layer up, by signedBytes, not here.
func TestResolveRejectsEscapes(t *testing.T) {
	p := &Profile{profilePath: "/srv/profile"}
	cases := map[string]string{
		"../outside/shared/x.json": "must not contain",
		"a/../../x.json":           "must not contain",
		"/etc/passwd":              "must be relative",
		`..\x.json`:                "backslash",
		"":                         "empty",
		"   ":                      "empty",
	}
	for rel, wantErr := range cases {
		got, err := p.resolve(rel)
		if err == nil {
			t.Fatalf("expected %q to be rejected, resolved to %q", rel, got)
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("resolve(%q) error = %q, want substring %q", rel, err.Error(), wantErr)
		}
	}

	key, err := p.resolve("actions/./ok.json")
	if err != nil {
		t.Fatalf("expected an ordinary relative reference to resolve, got %v", err)
	}
	if key != "actions/ok.json" {
		t.Fatalf("expected a normalized snapshot key, got %q", key)
	}
}

// TestSignedBytesRejectsUncovered is the other half: a well-shaped reference
// that the manifest never covered must fail rather than reach the filesystem.
func TestSignedBytesRejectsUncovered(t *testing.T) {
	p := &Profile{profilePath: "/srv/profile", files: map[string][]byte{"actions/a.json": []byte("{}")}}

	if _, err := p.signedBytes("actions/b.json"); err == nil || !strings.Contains(err.Error(), "not covered by the signed manifest") {
		t.Fatalf("expected uncovered reference error, got %v", err)
	}
	got, err := p.signedBytes("actions/a.json")
	if err != nil || string(got) != "{}" {
		t.Fatalf("expected covered reference to resolve, got %q %v", string(got), err)
	}
}
