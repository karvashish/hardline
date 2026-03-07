package profile

import (
	"os"
	"path/filepath"
	"runtime"
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
	repoRoot := mustRepoRoot(t)
	withChdir(t, repoRoot, func() {
		profileDir := t.TempDir()
		writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "broken-profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": []
}`)

		p, err := Load(profileDir)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		err = p.Affirm()
		if err == nil {
			t.Fatal("expected Affirm to fail for invalid loaded profile")
		}
		if !strings.Contains(err.Error(), "profile validation failed") {
			t.Fatalf("unexpected validation error: %v", err)
		}
	})
}

func TestAffirm_SucceedsForValidLoadedProfile(t *testing.T) {
	repoRoot := mustRepoRoot(t)
	withChdir(t, repoRoot, func() {
		profileDir := t.TempDir()
		writeFile(t, filepath.Join(profileDir, "profile.json"), `{
  "id": "ok-profile",
  "display_name": "OK Profile",
  "version": "1.0.0",
  "os": {"family": "ubuntu", "version": "24.04", "variant": "lts"},
  "profile_schema": 1,
  "min_hardline": "0.1.0",
  "actions": [],
  "templates": []
}`)

		p, err := Load(profileDir)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		if err := p.Affirm(); err != nil {
			t.Fatalf("expected Affirm success, got %v", err)
		}
	})
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func withChdir(t *testing.T, dir string, fn func()) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir to %q failed: %v", dir, err)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore cwd failed: %v", err)
		}
	}()
	fn()
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
