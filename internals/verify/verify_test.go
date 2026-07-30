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

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return nil, errors.New("sig bad") }

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "sig bad") {
		t.Fatalf("expected integrity error, got %v", err)
	}
}

func TestVerifyProfile_LoadError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) { return nil, errors.New("load boom") }

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "profile load failed") {
		t.Fatalf("expected load error, got %v", err)
	}
}

func TestVerifyProfile_AffirmError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return errors.New("schema invalid") }

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "profile schema validation failed") {
		t.Fatalf("expected affirm error, got %v", err)
	}
}

func TestVerifyProfile_PluginError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error {
		return errors.New("missing plugin")
	}

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "required plugin validation failed") {
		t.Fatalf("expected plugin error, got %v", err)
	}
}

func TestVerifyProfile_MissingTemplate(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) {
		return &VerifiedManifest{Files: map[string]struct{}{"templates/missing.tmpl": {}}}, nil
	}
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			Templates: []string{"templates/missing.tmpl"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }
	statFile = os.Stat

	err := verifyErr(cli.Command{Profile: t.TempDir()})
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

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) {
		return &VerifiedManifest{Files: map[string]struct{}{"templates/ok.tmpl": {}}}, nil
	}
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			Templates: []string{"templates/ok.tmpl"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }
	statFile = os.Stat

	err := verifyErr(cli.Command{Profile: dir})
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

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{
			AllowedOverrides: []string{"ssh_port"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }

	err := verifyErr(cli.Command{
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

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }

	err := verifyErr(cli.Command{Profile: "p"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

// verifyErr adapts the two-value Verify for tests that only assert the error.
func verifyErr(c cli.Command) error {
	_, err := Verify(c)
	return err
}

// emptyManifest stands in for a passed integrity check in tests that stub it
// out; coverage assertions treat an empty file set as "nothing is signed".
func emptyManifest() *VerifiedManifest {
	return &VerifiedManifest{Files: map[string]struct{}{}}
}

// TestVerifyProfile_ManifestCoverage pins the property that makes "signed" mean
// "every file we read is hashed": a declared action or template that the
// manifest does not list is unsigned content behind a signed pointer.
func TestVerifyProfile_ManifestCoverage(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "templates"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "templates", "t.tmpl"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile) error { return nil }
	statFile = os.Stat

	cases := []struct {
		name    string
		p       *profile.Profile
		signed  map[string]struct{}
		wantErr string
	}{
		{
			name:    "declared action not in manifest",
			p:       &profile.Profile{Actions: []string{"actions/a.json"}},
			signed:  map[string]struct{}{"profile.json": {}},
			wantErr: `action "actions/a.json" declared in profile.json is not covered`,
		},
		{
			name:    "declared template not in manifest",
			p:       &profile.Profile{Templates: []string{"templates/t.tmpl"}},
			signed:  map[string]struct{}{"profile.json": {}},
			wantErr: `template "templates/t.tmpl" declared in profile.json is not covered`,
		},
		{
			name:    "escaping action reference",
			p:       &profile.Profile{Actions: []string{"../shared/x.json"}},
			signed:  map[string]struct{}{"profile.json": {}},
			wantErr: "not a valid profile-relative path",
		},
		{
			name:    "absolute action reference",
			p:       &profile.Profile{Actions: []string{"/etc/hardline/x.json"}},
			signed:  map[string]struct{}{"profile.json": {}},
			wantErr: "not a valid profile-relative path",
		},
		{
			name:    "fully covered profile passes",
			p:       &profile.Profile{Actions: []string{"actions/a.json"}, Templates: []string{"templates/t.tmpl"}},
			signed:  map[string]struct{}{"actions/a.json": {}, "templates/t.tmpl": {}},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifyIntegrity = func(string, bool) (*VerifiedManifest, error) {
				return &VerifiedManifest{Digest: "d", Files: tc.signed}, nil
			}
			loadVerifyProfile = func(string) (*profile.Profile, error) { return tc.p, nil }

			err := verifyErr(cli.Command{Profile: dir})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected %q, got %v", tc.wantErr, err)
			}
		})
	}
}
