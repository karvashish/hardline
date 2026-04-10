package verify

import (
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

func Verify(c cli.Command) error {
	logger.Debugf("verify-profile: profile=%q\n", c.Profile)

	if err := verifyIntegrity(c.Profile, c.AllowLocalKey); err != nil {
		return err
	}

	p, err := loadVerifyProfile(c.Profile)
	if err != nil {
		return logger.Wrap(err, "profile load failed")
	}

	if err := affirmProfile(p); err != nil {
		return logger.Wrap(err, "profile schema validation failed")
	}

	overrides, err := cli.ResolveOverrides(c)
	if err != nil {
		return logger.Wrap(err, "resolve runtime overrides")
	}
	if err := p.ValidateOverrides(overrides); err != nil {
		return logger.Wrap(err, "profile override validation failed")
	}

	if err := ensureVerifyPlugins(registry.Shared(), p); err != nil {
		return logger.Wrap(err, "required plugin validation failed")
	}

	for _, tmpl := range p.Templates {
		tmplPath := filepath.Join(c.Profile, tmpl)
		if _, err := statFile(tmplPath); err != nil {
			return logger.Wrap(err, "template "+strconv.Quote(tmpl)+" declared in profile.json but missing on disk")
		}
	}

	return nil
}
