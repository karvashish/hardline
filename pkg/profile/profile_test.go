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

	t.Run("undeclared template", func(t *testing.T) {
		dir := t.TempDir()
		writeProfileJSON(t, dir, []string{"actions/a.json"}, []string{"templates/declared.tmpl"})
		writeFile(t, filepath.Join(dir, "actions", "a.json"), `{
  "steps": [
    {
      "id": "tmpl",
      "type": "template",
      "template": {"src": "templates/not-declared.tmpl", "dest": "/tmp/x", "mode": "0644"}
    }
  ]
}`)
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "uses undeclared template") {
			t.Fatalf("expected undeclared template error, got %v", err)
		}
	})

	t.Run("undeclared firewall template", func(t *testing.T) {
		dir := t.TempDir()
		writeProfileJSON(t, dir, []string{"actions/a.json"}, []string{"templates/declared.tmpl"})
		writeFile(t, filepath.Join(dir, "actions", "a.json"), `{
  "steps": [
    {
      "id": "fw",
      "type": "firewall_template",
      "firewall_template": {"backend": "nftables", "policy": "deny", "template_src": "templates/not-declared.tmpl", "template_dest": "/etc/nftables.conf", "allow": []}
    }
  ]
}`)
		if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "uses undeclared firewall template") {
			t.Fatalf("expected undeclared firewall template error, got %v", err)
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
      "type": "template",
      "template": {"src": "templates/t.tmpl", "dest": "/etc/example.conf", "mode": "0644"}
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
