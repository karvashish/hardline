package verify

import (
	"encoding/json"
	"fmt"

	"github.com/karvashish/hardline/internals/cli"
	"github.com/karvashish/hardline/internals/registry"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
)

var (
	verifyIntegrity     = VerifyProfileIntegrity
	loadVerifyProfile   = profile.LoadFromBundle
	ensureVerifyPlugins = pluginapi.ValidateProfileSteps
	affirmProfile       = func(p *profile.Profile) error { return p.Affirm() }
	resolveOverrides    = cli.ResolveOverrides
)

// VerifiedBundle is the immutable result of a passed verify phase. Plan, apply
// and rollback take this instead of a directory path so they operate on the
// profile whose signature was checked, rather than re-reading a directory that
// may have changed since.
//
// Overrides are carried here for the same reason, even though they are
// deliberately unsigned: resolving them separately in each phase lets apply act
// on values the plan never displayed.
type VerifiedBundle struct {
	ProfileDir     string
	ManifestDigest string
	Profile        *profile.Profile
	Overrides      map[string]json.RawMessage
}

func Verify(c cli.Command) (*VerifiedBundle, error) {
	logger.Debugf("verify-profile: profile=%q\n", c.Profile)

	manifest, err := verifyIntegrity(c.Profile, c.AllowLocalKey)
	if err != nil {
		return nil, err
	}

	p, err := loadVerifyProfile(c.Profile, manifest.Files)
	if err != nil {
		return nil, logger.Wrap(err, "profile load failed")
	}

	if err := affirmProfile(p); err != nil {
		return nil, logger.Wrap(err, "profile schema validation failed")
	}

	overrides, err := resolveOverrides(c)
	if err != nil {
		return nil, logger.Wrap(err, "resolve runtime overrides")
	}
	if err := p.ValidateOverrides(overrides); err != nil {
		return nil, logger.Wrap(err, "profile override validation failed")
	}

	if err := ensureVerifyPlugins(registry.Shared(), p, overrides); err != nil {
		return nil, logger.Wrap(err, "step validation failed")
	}

	// A reference outside the signed tree is unsigned content reached through a
	// signed pointer. The profile is already loaded from the snapshot, so an
	// uncovered action would have failed above; templates are loaded lazily and
	// this is where they are proven covered.
	if err := assertManifestCoverage(manifest, "action", p.Actions); err != nil {
		return nil, err
	}
	if err := assertManifestCoverage(manifest, "template", p.Templates); err != nil {
		return nil, err
	}
	if p.CoverageLedger != "" {
		if err := assertManifestCoverage(manifest, "coverage ledger", []string{p.CoverageLedger}); err != nil {
			return nil, err
		}
	}

	return &VerifiedBundle{
		ProfileDir:     c.Profile,
		ManifestDigest: manifest.Digest,
		Profile:        p,
		Overrides:      overrides,
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
