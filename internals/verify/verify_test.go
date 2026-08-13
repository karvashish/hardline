package verify

import (
	"encoding/json"
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
	prevOverrides := resolveOverrides

	return func() {
		verifyIntegrity = prevIntegrity
		loadVerifyProfile = prevLoad
		ensureVerifyPlugins = prevEnsure
		affirmProfile = prevAffirm
		resolveOverrides = prevOverrides
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
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) { return nil, errors.New("load boom") }

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "profile load failed") {
		t.Fatalf("expected load error, got %v", err)
	}
}

func TestVerifyProfile_AffirmError(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
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
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error {
		return errors.New("missing plugin")
	}

	err := verifyErr(cli.Command{Profile: "p"})
	if err == nil || !strings.Contains(err.Error(), "step validation failed") {
		t.Fatalf("expected plugin error, got %v", err)
	}
}

func TestVerifyProfile_TemplateCoveredBySnapshot(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) {
		return &VerifiedManifest{Files: map[string][]byte{"templates/ok.tmpl": []byte("x")}}, nil
	}
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{
			Templates: []string{"templates/ok.tmpl"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error { return nil }

	err := verifyErr(cli.Command{Profile: filepath.Join(t.TempDir(), "gone")})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestVerifyProfile_CarriesOverrideSnapshot(t *testing.T) {
	restore := stubVerifyHooks()
	defer restore()

	dir := t.TempDir()
	overridesPath := filepath.Join(dir, "overrides.json")
	if err := os.WriteFile(overridesPath, []byte(`{"ssh_port": 2222}`), 0o644); err != nil {
		t.Fatal(err)
	}

	verifyIntegrity = func(string, bool) (*VerifiedManifest, error) { return emptyManifest(), nil }
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{AllowedOverrides: []string{"ssh_port"}}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error { return nil }

	bundle, err := Verify(cli.Command{Profile: dir, OverridesFile: overridesPath})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got := string(bundle.Overrides["ssh_port"]); got != "2222" {
		t.Fatalf("expected the resolved override on the bundle, got %q", got)
	}

	if err := os.WriteFile(overridesPath, []byte(`{"ssh_port": 23}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := string(bundle.Overrides["ssh_port"]); got != "2222" {
		t.Fatalf("bundle override changed to %q after the file was edited", got)
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
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{
			AllowedOverrides: []string{"ssh_port"},
		}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error { return nil }

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
	loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) {
		return &profile.Profile{}, nil
	}
	affirmProfile = func(*profile.Profile) error { return nil }
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error { return nil }

	err := verifyErr(cli.Command{Profile: "p"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func verifyErr(c cli.Command) error {
	_, err := Verify(c)
	return err
}

func emptyManifest() *VerifiedManifest {
	return &VerifiedManifest{Files: map[string][]byte{}}
}

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
	ensureVerifyPlugins = func(_ *pluginapi.Registry, _ *profile.Profile, _ map[string]json.RawMessage) error { return nil }

	cases := []struct {
		name    string
		p       *profile.Profile
		signed  map[string][]byte
		wantErr string
	}{
		{
			name:    "declared action not in manifest",
			p:       &profile.Profile{Actions: []string{"actions/a.json"}},
			signed:  map[string][]byte{"profile.json": nil},
			wantErr: `action "actions/a.json" declared in profile.json is not covered`,
		},
		{
			name:    "declared template not in manifest",
			p:       &profile.Profile{Templates: []string{"templates/t.tmpl"}},
			signed:  map[string][]byte{"profile.json": nil},
			wantErr: `template "templates/t.tmpl" declared in profile.json is not covered`,
		},
		{
			name:    "escaping action reference",
			p:       &profile.Profile{Actions: []string{"../shared/x.json"}},
			signed:  map[string][]byte{"profile.json": nil},
			wantErr: "not a valid profile-relative path",
		},
		{
			name:    "absolute action reference",
			p:       &profile.Profile{Actions: []string{"/etc/hardline/x.json"}},
			signed:  map[string][]byte{"profile.json": nil},
			wantErr: "not a valid profile-relative path",
		},
		{
			name:    "fully covered profile passes",
			p:       &profile.Profile{Actions: []string{"actions/a.json"}, Templates: []string{"templates/t.tmpl"}},
			signed:  map[string][]byte{"actions/a.json": nil, "templates/t.tmpl": nil},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verifyIntegrity = func(string, bool) (*VerifiedManifest, error) {
				return &VerifiedManifest{Digest: "d", Files: tc.signed}, nil
			}
			loadVerifyProfile = func(string, map[string][]byte) (*profile.Profile, error) { return tc.p, nil }

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
