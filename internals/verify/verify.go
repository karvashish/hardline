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

type VerifiedBundle struct {
	Profile   *profile.Profile
	Overrides map[string]json.RawMessage
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

	if err := assertManifestCoverage(manifest, "action", p.Actions); err != nil {
		return nil, err
	}
	if err := assertManifestCoverage(manifest, "template", p.Templates); err != nil {
		return nil, err
	}
	return &VerifiedBundle{
		Profile:   p,
		Overrides: overrides,
	}, nil
}

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
