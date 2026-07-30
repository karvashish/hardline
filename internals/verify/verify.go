package verify

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var (
	verifyIntegrity     = VerifyProfileIntegrity
	loadVerifyProfile   = profile.Load
	ensureVerifyPlugins = pluginapi.EnsureProfilePlugins
	affirmProfile       = func(p *profile.Profile) error { return p.Affirm() }
	statFile            = os.Stat
)

// VerifiedBundle is the immutable result of a passed verify phase. Plan, apply
// and rollback take this instead of a directory path so they operate on the
// profile whose signature was checked, rather than re-reading a directory that
// may have changed since.
type VerifiedBundle struct {
	ProfileDir     string
	ManifestDigest string
	Profile        *profile.Profile
}

func Verify(c cli.Command) (*VerifiedBundle, error) {
	logger.Debugf("verify-profile: profile=%q\n", c.Profile)

	manifest, err := verifyIntegrity(c.Profile, c.AllowLocalKey)
	if err != nil {
		return nil, err
	}

	p, err := loadVerifyProfile(c.Profile)
	if err != nil {
		return nil, logger.Wrap(err, "profile load failed")
	}

	if err := affirmProfile(p); err != nil {
		return nil, logger.Wrap(err, "profile schema validation failed")
	}

	overrides, err := cli.ResolveOverrides(c)
	if err != nil {
		return nil, logger.Wrap(err, "resolve runtime overrides")
	}
	if err := p.ValidateOverrides(overrides); err != nil {
		return nil, logger.Wrap(err, "profile override validation failed")
	}

	if err := ensureVerifyPlugins(registry.Shared(), p); err != nil {
		return nil, logger.Wrap(err, "required plugin validation failed")
	}

	// Coverage first: it rejects any reference that points outside the signed
	// tree, so the stat below never touches a path the signature did not cover.
	if err := assertManifestCoverage(manifest, "action", p.Actions); err != nil {
		return nil, err
	}
	if err := assertManifestCoverage(manifest, "template", p.Templates); err != nil {
		return nil, err
	}

	for _, tmpl := range p.Templates {
		tmplPath := filepath.Join(c.Profile, tmpl)
		if _, err := statFile(tmplPath); err != nil {
			return nil, logger.Wrap(err, "template "+strconv.Quote(tmpl)+" declared in profile.json but missing on disk")
		}
	}

	return &VerifiedBundle{
		ProfileDir:     c.Profile,
		ManifestDigest: manifest.Digest,
		Profile:        p,
	}, nil
}

// assertManifestCoverage is what makes "signed" mean "every file we read is
// hashed" rather than "the file list is hashed". A reference outside the hashed
// tree is unsigned content reached through a signed pointer.
func assertManifestCoverage(manifest *VerifiedManifest, kind string, rels []string) error {
	for _, rel := range rels {
		normalized, err := normalizeManifestPath(rel)
		if err != nil {
			return fmt.Errorf("%s %q declared in profile.json is not a valid profile-relative path: %w", kind, rel, err)
		}
		if _, ok := manifest.Files[normalized]; !ok {
			return fmt.Errorf("%s %q declared in profile.json is not covered by the signed manifest", kind, rel)
		}
	}
	return nil
}
