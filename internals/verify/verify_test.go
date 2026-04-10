package verify

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

func stubVerifyHooks() func() {
	prevIntegrity := verifyIntegrity
	prevLoad := loadVerifyProfile
	prevEnsure := ensureVerifyPlugins
	prevAffirm := affirmProfile
	prevStat := statFile

	return func() {
		verifyIntegrity = prevIntegrity
		loadVerifyProfile = prevLoad
		ensureVerifyPlugins = prevEnsure
		affirmProfile = prevAffirm
		statFile = prevStat
	}
}

func TestVerifyProfile_IntegrityError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return errors.New("sig bad") }

	err := Verify(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "sig bad") {
		t.Fatalf("expected integrity error, got %v", err)
	}
}

func TestVerifyProfile_LoadError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) { return nil, errors.New("load boom") }

	err := Verify(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "profile load failed") {
		t.Fatalf("expected load error, got %v", err)
	}
}

func TestVerifyProfile_AffirmError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return errors.New("schema invalid") }

	err := Verify(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "profile schema validation failed") {
		t.Fatalf("expected affirm error, got %v", err)
	}
}

func TestVerifyProfile_PluginError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error {
		return errors.New("missing plugin")
	}

	err := Verify(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "required plugin validation failed") {
		t.Fatalf("expected plugin error, got %v", err)
	}
}

func TestVerifyProfile_MissingTemplate(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			Templates: []string{"templates/missing.tmpl"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }
	statFile = os.Stat

	err := Verify(cli.Command{Profile: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "missing on disk") {
		t.Fatalf("expected missing template error, got %v", err)
	}
}

func TestVerifyProfile_TemplateExists(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	dir := t.TempDir()
	tmplDir := filepath.Join(dir, "templates")
	if err := os.MkdirAll(tmplDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmplDir, "ok.tmpl"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			Templates: []string{"templates/ok.tmpl"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }
	statFile = os.Stat

	err := Verify(cli.Command{Profile: dir})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestVerifyProfile_OverrideValidation(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	dir := t.TempDir()
	overridesPath := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(overridesPath, []byte(`{"smtp_port": 25}`), 0o644); err != nil {
		t.Fatal(err)
	}

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			AllowedOverrides: []string{"ssh_port"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }

	err := Verify(cli.Command{
		Profile:       "p",
		OverridesFile: overridesPath,
	})
	if err == nil || !strings.Contains(err.Error(), "override validation") {
		t.Fatalf("expected override validation error, got %v", err)
	}
}

func TestVerifyProfile_Success(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) error { return nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }

	err := Verify(cli.Command{Profile: "p"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}
