package profile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
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
      "plugin": "packages_apt",
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

func TestAffirm_ValidatesOSDeclaration(t *testing.T) {
	cases := []struct {
		name    string
		family  string
		version string
		wantErr bool
	}{
		{name: "major-only version", family: "rocky", version: "9"},
		{name: "point version", family: "ubuntu", version: "24.04"},
		{name: "empty family", family: "", version: "9", wantErr: true},
		{name: "malformed family", family: "rocky linux", version: "9", wantErr: true},
		{name: "empty version", family: "rocky", version: "", wantErr: true},
		{name: "malformed version", family: "rocky", version: "9.x", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileDir := t.TempDir()
			writeFile(t, filepath.Join(profileDir, "profile.json"), fmt.Sprintf(`{
  "id": "os-validation",
  "display_name": "OS Validation",
  "version": "1.0.0",
  "os": {"family": %q, "version": %q, "variant": "server"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": [],
  "allowed_overrides": []
}`, tc.family, tc.version))

			p, err := Load(profileDir)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			err = p.Affirm()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "profile validation failed") {
					t.Fatalf("expected OS schema validation error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected valid OS declaration, got %v", err)
			}
		})
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

	setSchemaFSForTest(t, fstest.MapFS{})
	if err := p.Affirm(); err == nil {
		t.Fatal("expected schema read failure")
	}

	setSchemaFSForTest(t, fstest.MapFS{
		"profile.schema.json": &fstest.MapFile{Data: []byte("{not-json")},
	})
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

// TestSchemasLoadFromEmbeddedFS makes no assumption about a source tree on
// disk: a release archive ships the binary alone, so this is what proves a
// released hardline can still validate a profile.
func TestSchemasLoadFromEmbeddedFS(t *testing.T) {
	for _, name := range []string{profileSchemaName, actionFileSchemaName} {
		if _, err := loadResolvedSchema(name); err != nil {
			t.Fatalf("load embedded schema %q: %v", name, err)
		}
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

func setSchemaFSForTest(t *testing.T, fsys fs.FS) {
	t.Helper()
	prev := schemaFS
	schemaFS = fsys
	t.Cleanup(func() {
		schemaFS = prev
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

// TestAffirm_RejectsPluginConfigInjection pins the schema layer of the
// injection defence: a hostile value must fail at verify, before hardline
// connects to any host, not later when the plugin builds a root command.
func TestAffirm_RejectsPluginConfigInjection(t *testing.T) {
	cases := map[string]string{
		"service": `{"id":"s","plugin":"service","config":{"name":"ssh$(touch /tmp/hardline-pwn)"}}`,
		"file_meta path": `{"id":"s","plugin":"file_meta",
			"config":{"path":"/etc/99-hardline$(id).conf","mode":"0600"}}`,
		"file_meta owner": `{"id":"s","plugin":"file_meta",
			"config":{"path":"/etc/shadow","owner":"root;id"}}`,
		"template dest": `{"id":"s","plugin":"template",
			"config":{"src":"templates/c.tmpl","dest":"/etc/99-hardline` + "`id`" + `.conf"}}`,
		"template src": `{"id":"s","plugin":"template",
			"config":{"src":"../shared/c.tmpl","dest":"/etc/99-hardline.conf"}}`,
		"firewall dest": `{"id":"s","plugin":"firewall",
			"config":{"managed_dest":"/etc/nftables.d/99-hardline$(id).nft"}}`,
		"packages_apt install": `{"id":"s","plugin":"packages_apt","config":{"install":["curl;id"]}}`,
		"packages_dnf4 install": `{"id":"s","plugin":"packages_dnf4","config":{"install":["curl;id"]}}`,
	}

	for name, step := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, filepath.Join(dir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json"],
  "templates": []
}`)
			writeFile(t, filepath.Join(dir, "actions", "a.json"), `{"steps":[`+step+`]}`)

			p, err := Load(dir)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			if err := p.Affirm(); err == nil {
				t.Fatal("expected the hostile step to be rejected at verify")
			}
		})
	}
}

// TestAffirm_AcceptsOrdinaryPluginConfig guards the same patterns against
// being so tight that a real profile stops validating.
func TestAffirm_AcceptsOrdinaryPluginConfig(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": ["actions/a.json"],
  "templates": []
}`)
	writeFile(t, filepath.Join(dir, "actions", "a.json"), `{"steps":[
  {"id":"svc","plugin":"service","config":{"name":"getty@tty1.service","state":"started"}},
  {"id":"fm","plugin":"file_meta","config":{"path":"/etc/shadow","owner":"root","group":"shadow","mode":"0640"}},
  {"id":"tpl","plugin":"template","config":{"src":"templates/c.tmpl","dest":"/etc/ssh/sshd_config.d/99-hardline.conf"}},
  {"id":"fw","plugin":"firewall","config":{"main_config":"/etc/nftables.conf","managed_dest":"/etc/nftables.d/99-hardline.nft"}},
  {"id":"pkg","plugin":"packages_dnf4","config":{"install":["curl","libssl3"],"purge":["telnet"]}}
]}`)

	p, err := Load(dir)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := p.Affirm(); err != nil {
		t.Fatalf("expected an ordinary profile to validate, got %v", err)
	}
}
