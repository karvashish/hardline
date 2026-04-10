package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAffirm_RequiresLoadedProfilePath(t *testing.T) {
	p := &Profile{}
	err := p.Affirm()
	if err == nil {
		t.Fatal("expected Affirm to fail when profile path is empty")
	}
	if !strings.Contains(err.Error(), "load profile before validation") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAffirm_UsesLoadedProfilePath(t *testing.T) {
	profileDir := t.TempDir()
	writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "broken-profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`)

	p := &Profile{profilePath: profileDir}
	err := p.Affirm()
	if err == nil {
		t.Fatal("expected Affirm to fail for invalid loaded profile")
	}
	if !strings.Contains(err.Error(), "profile validation failed") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestAffirm_SucceedsForValidLoadedProfile(t *testing.T) {
	profileDir := t.TempDir()
	writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/ok.json"],
  "templates": [],
  "allowed_overrides": []
}`)
	writeFile(t, filepath.Join(profileDir, "actions", "ok.json"), `{
  "steps": [
    {
      "id": "pkg",
      "plugin": "packages",
      "config": {"install": ["curl"]}
    }
  ]
}`)

	p, err := Load(profileDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := p.Affirm(); err != nil {
		t.Fatalf("expected Affirm success, got %v", err)
	}
}

func TestAffirm_ProfileReadAndDecodeErrors(t *testing.T) {
	missing := &Profile{profilePath: t.TempDir()}
	if err := missing.Affirm(); err == nil || !strings.Contains(err.Error(), "read profile json") {
		t.Fatalf("expected read profile json error, got %v", err)
	}

	invalidDir := t.TempDir()
	writeFile(t, filepath.Join(invalidDir, "profile.json"), "{bad-json")
	invalid := &Profile{profilePath: invalidDir}
	if err := invalid.Affirm(); err == nil || !strings.Contains(err.Error(), "decode profile json") {
		t.Fatalf("expected decode profile json error, got %v", err)
	}
}

func TestAffirm_SchemaReadAndParseErrors(t *testing.T) {
	profileDir := t.TempDir()
	writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`)
	p := &Profile{profilePath: profileDir}

	setSchemaPathResolverForTest(t, func() string {
		return filepath.Join(t.TempDir(), "missing.schema.json")
	})
	if err := p.Affirm(); err == nil {
		t.Fatal("expected schema read failure")
	}

	invalidSchema := filepath.Join(t.TempDir(), "profile.schema.json")
	writeFile(t, invalidSchema, "{not-json")
	setSchemaPathResolverForTest(t, func() string { return invalidSchema })
	if err := p.Affirm(); err == nil {
		t.Fatal("expected invalid schema parse failure")
	}
}

func TestAffirm_ActionFileReadAndDecodeErrors(t *testing.T) {
	t.Run("missing action file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/missing.json"],
  "templates": [],
  "allowed_overrides": []
}`)
		p := &Profile{profilePath: dir}
		if err := p.Affirm(); err == nil || !strings.Contains(err.Error(), "read action file") {
			t.Fatalf("expected action file read error, got %v", err)
		}
	})

	t.Run("invalid action file", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/invalid.json"],
  "templates": [],
  "allowed_overrides": []
}`)
		writeFile(t, filepath.Join(dir, "actions", "invalid.json"), "{bad-json")
		p := &Profile{profilePath: dir}
		if err := p.Affirm(); err == nil || !strings.Contains(err.Error(), "decode action file") {
			t.Fatalf("expected action file decode error, got %v", err)
		}
	})
}

func TestProfileSchemaPath_ResolvesSchemaFile(t *testing.T) {
	p := resolveProfileSchemaPath()
	if !strings.HasSuffix(filepath.ToSlash(p), "schema/profile.schema.json") {
		t.Fatalf("unexpected schema path %q", p)
	}
}

func TestActionFileSchemaPath_ResolvesSchemaFile(t *testing.T) {
	p := resolveActionFileSchemaPath()
	if !strings.HasSuffix(filepath.ToSlash(p), "schema/action-file.schema.json") {
		t.Fatalf("unexpected schema path %q", p)
	}
}

func TestAffirm_ValidatesActionFiles(t *testing.T) {
	profileDir := t.TempDir()
	writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/invalid.json"],
  "templates": [],
  "allowed_overrides": []
}`)
	writeFile(t, filepath.Join(profileDir, "actions", "invalid.json"), `{
  "steps": [
    {
      "id": "svc",
      "plugin": "service",
      "name": "ssh"
    }
  ]
}`)

	p, err := Load(profileDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	err = p.Affirm()
	if err == nil || !strings.Contains(err.Error(), "action file validation failed") {
		t.Fatalf("expected action schema validation error, got %v", err)
	}
}

func TestAffirm_ValidatesDeclaredOverrides(t *testing.T) {
	profileDir := t.TempDir()
	writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": ["ssh_port", "ssh_port"]
}`)

	p, err := Load(profileDir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	err = p.Affirm()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate allowed_overrides error, got %v", err)
	}
}

func setSchemaPathResolverForTest(t *testing.T, fn func() string) {
	t.Helper()
	prev := resolveProfileSchemaPath
	resolveProfileSchemaPath = fn
	t.Cleanup(func() {
		resolveProfileSchemaPath = prev
	})
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll for %q failed: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile %q failed: %v", path, err)
	}
}
