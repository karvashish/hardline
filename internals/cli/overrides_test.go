package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOverrides_AutoLoadsDefaultFile(t *testing.T) {
	profileDir := t.TempDir()
	writeOverridesFile(t, filepath.Join(profileDir, DefaultOverridesFilename), `{
  "ssh_port": 2222,
  "firewall": {"allow": [22]}
}`)

	merged, err := ResolveOverrides(Command{Profile: profileDir})
	if err != nil {
		t.Fatalf("ResolveOverrides failed: %v", err)
	}
	if string(merged["ssh_port"]) != "2222" {
		t.Fatalf("expected ssh_port override, got %+v", merged)
	}

	var firewallPayload struct {
		Allow []int `json:"allow"`
	}
	if err := json.Unmarshal(merged["firewall"], &firewallPayload); err != nil {
		t.Fatalf("expected nested JSON payload to stay valid, got err=%v payload=%s", err, string(merged["firewall"]))
	}
	if len(firewallPayload.Allow) != 1 || firewallPayload.Allow[0] != 22 {
		t.Fatalf("expected nested JSON payload to be preserved, got %+v", firewallPayload)
	}
}

func TestResolveOverrides_ExplicitFileOverridesDefault(t *testing.T) {
	profileDir := t.TempDir()
	writeOverridesFile(t, filepath.Join(profileDir, DefaultOverridesFilename), `{"ssh_port": 2222}`)
	explicitPath := filepath.Join(t.TempDir(), "custom.json")
	writeOverridesFile(t, explicitPath, `{"ssh_port": 2022}`)

	merged, err := ResolveOverrides(Command{
		Profile:       profileDir,
		OverridesFile: explicitPath,
	})
	if err != nil {
		t.Fatalf("ResolveOverrides failed: %v", err)
	}
	if string(merged["ssh_port"]) != "2022" {
		t.Fatalf("expected explicit overrides file to win, got %+v", merged)
	}
}

func TestResolveOverrides_RejectsNonObjectFiles(t *testing.T) {
	profileDir := t.TempDir()
	path := filepath.Join(profileDir, DefaultOverridesFilename)
	writeOverridesFile(t, path, `["bad"]`)

	if _, err := ResolveOverrides(Command{Profile: profileDir}); err == nil {
		t.Fatal("expected non-object override file to fail")
	}
}

func TestResolveOverrides_ReturnsNilWhenNothingToLoad(t *testing.T) {
	if got, err := ResolveOverrides(Command{}); err != nil || got != nil {
		t.Fatalf("expected nil overrides with empty command, got=%+v err=%v", got, err)
	}

	if got, err := ResolveOverrides(Command{Profile: t.TempDir()}); err != nil || got != nil {
		t.Fatalf("expected nil overrides when profile dir has no default file, got=%+v err=%v", got, err)
	}
}

func TestResolveOverrides_ExplicitMissingFileFails(t *testing.T) {
	_, err := ResolveOverrides(Command{OverridesFile: filepath.Join(t.TempDir(), "missing.json")})
	if err == nil {
		t.Fatal("expected missing explicit overrides file to fail")
	}
}

func TestLoadOverridesFile_ReportsMissingFile(t *testing.T) {
	if _, err := loadOverridesFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("expected missing overrides file to fail")
	}
}

func writeOverridesFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for override file: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write override file: %v", err)
	}
}
