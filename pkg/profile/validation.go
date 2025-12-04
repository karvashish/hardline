package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
)

// Affirm performs in-memory validation of the loaded profile and all action files.
// Assumes Load has already been called successfully so that ActionFiles is populated
// and template references have been checked.

func (o OSInfo) Affirm() error {
	logger.Debugf("profile: validating os info: family=%q version=%q variant=%q", o.Family, o.Version, o.Variant)

	if strings.TrimSpace(o.Family) == "" {
		return fmt.Errorf("os.family is required")
	}
	if strings.TrimSpace(o.Version) == "" {
		return fmt.Errorf("os.version is required")
	}
	if strings.TrimSpace(o.Variant) == "" {
		return fmt.Errorf("os.variant is required")
	}
	return nil
}

func (p *Profile) Affirm() error {
	logger.Debugf("profile: validating profile id=%q display_name=%q version=%q schema=%d actions=%d templates=%d",
		p.ID, p.DisplayName, p.Version, p.ProfileSchema, len(p.Actions), len(p.Templates))

	totalSteps := 0
	for _, af := range p.ActionFiles {
		totalSteps += len(af.Steps)
	}
	fmt.Fprintf(os.Stderr,
		"profile %s: %d actions, %d templates, %d steps\n",
		p.ID, len(p.Actions), len(p.Templates), totalSteps,
	)

	if strings.TrimSpace(p.ID) == "" {
		return fmt.Errorf("profile.id is required")
	}
	if strings.TrimSpace(p.DisplayName) == "" {
		return fmt.Errorf("profile.display_name is required")
	}
	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("profile.version is required")
	}
	if p.ProfileSchema <= 0 {
		return fmt.Errorf("profile.profile_schema must be >= 1")
	}
	if strings.TrimSpace(p.MinHardline) == "" {
		return fmt.Errorf("profile.min_hardline is required")
	}
	if len(p.Actions) == 0 {
		return fmt.Errorf("profile.actions must contain at least one action file")
	}

	if err := p.OS.Affirm(); err != nil {
		return fmt.Errorf("profile.os: %w", err)
	}

	if len(p.ActionFiles) != len(p.Actions) {
		return fmt.Errorf("profile.ActionFiles not fully loaded (expected %d, have %d)", len(p.Actions), len(p.ActionFiles))
	}

	for _, af := range p.ActionFiles {
		if err := af.Affirm(); err != nil {
			return err
		}
	}

	logger.Debugf("profile: validation completed successfully for profile id=%q", p.ID)
	fmt.Fprintf(os.Stderr, "profile %s: validation OK\n", p.ID)

	return nil
}

func (pk PackageSpec) Affirm() error {
	logger.Debugf("profile: validating packages spec: update=%v upgrade=%v autoremove=%v install=%d purge=%d",
		pk.Update, pk.Upgrade, pk.Autoremove, len(pk.Install), len(pk.Purge))

	if !pk.Update && !pk.Upgrade && !pk.Autoremove && len(pk.Install) == 0 && len(pk.Purge) == 0 {
		return fmt.Errorf("packages step must specify at least one of update/upgrade/autoremove/install/purge")
	}
	return nil
}

func (t TemplateSpec) Affirm() error {
	logger.Debugf("profile: validating template spec: src=%q dest=%q mode=%q", t.Src, t.Dest, t.Mode)

	if strings.TrimSpace(t.Src) == "" {
		return fmt.Errorf("template.src is required")
	}
	if strings.TrimSpace(t.Dest) == "" {
		return fmt.Errorf("template.dest is required")
	}
	if !filepath.IsAbs(t.Dest) {
		return fmt.Errorf("template.dest %q must be an absolute path", t.Dest)
	}
	if strings.TrimSpace(t.Mode) == "" {
		return fmt.Errorf("template.mode is required")
	}

	var parsed uint64
	if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err != nil {
		return fmt.Errorf("template.mode %q is not valid octal: %w", t.Mode, err)
	}

	return nil
}

func (s ServiceSpec) Affirm() error {
	logger.Debugf("profile: validating service spec: name=%q enabled=%v state=%q", s.Name, s.Enabled, s.State)

	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("service.name is required")
	}

	state := strings.TrimSpace(s.State)
	if state == "" {
		return nil
	}

	switch state {
	case "started", "stopped", "restarted", "reloaded":
		return nil
	default:
		return fmt.Errorf("service.state %q is invalid (must be started, stopped, restarted, or reloaded)", s.State)
	}
}

func (r FirewallRule) Affirm() error {
	logger.Debugf("profile: validating firewall rule: port=%d proto=%q", r.Port, r.Proto)

	if r.Port <= 0 || r.Port > 65535 {
		return fmt.Errorf("firewall rule port %d out of range (1-65535)", r.Port)
	}

	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	switch proto {
	case "tcp", "udp":
		return nil
	default:
		return fmt.Errorf("firewall rule proto %q invalid (must be tcp or udp)", r.Proto)
	}
}

func (f FirewallSpec) Affirm() error {
	logger.Debugf("profile: validating firewall spec: backend=%q policy=%q template_src=%q template_dest=%q allow_rules=%d",
		f.Backend, f.Policy, f.TemplateSrc, f.TemplateDest, len(f.Allow))

	switch f.Backend {
	case "nftables":
		// ok
	case "ufw", "iptables", "firewalld":
		return fmt.Errorf("firewall.backend %q is not supported (only nftables is currently supported)", f.Backend)
	default:
		return fmt.Errorf("firewall.backend %q is invalid (must be nftables)", f.Backend)
	}

	switch f.Policy {
	case "allow", "deny", "reject", "drop":
	default:
		return fmt.Errorf("firewall.policy %q is invalid (must be allow, deny, reject, or drop)", f.Policy)
	}

	if f.TemplateDest != "" && !filepath.IsAbs(f.TemplateDest) {
		return fmt.Errorf("firewall.template_dest %q must be an absolute path if set", f.TemplateDest)
	}

	for i, rule := range f.Allow {
		if err := rule.Affirm(); err != nil {
			return fmt.Errorf("firewall.allow[%d]: %w", i, err)
		}
	}

	return nil
}

func (s Step) Affirm() error {
	logger.Debugf("profile: validating step id=%q type=%q severity=%q risk_class=%q", s.ID, s.Type, s.Severity, s.RiskClass)

	if strings.TrimSpace(s.ID) == "" {
		return fmt.Errorf("step.id is required")
	}

	stepType := strings.ToLower(strings.TrimSpace(s.Type))
	switch stepType {
	case "packages", "template", "service", "firewall", "validate":
	default:
		return fmt.Errorf("step %q: invalid type %q", s.ID, s.Type)
	}

	switch s.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("step %q: invalid severity %q", s.ID, s.Severity)
	}

	switch s.RiskClass {
	case "none", "access", "availability", "data_loss", "integrity", "compliance", "other":
	default:
		return fmt.Errorf("step %q: invalid risk_class %q", s.ID, s.RiskClass)
	}

	switch stepType {

	case "packages":
		if s.Packages == nil {
			return fmt.Errorf("step %q (type=packages): packages spec is required", s.ID)
		}
		if s.Template != nil || s.Service != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			return fmt.Errorf("step %q (type=packages): only packages may be set", s.ID)
		}
		if err := s.Packages.Affirm(); err != nil {
			return fmt.Errorf("step %q: %w", s.ID, err)
		}

	case "template":
		if s.Template == nil {
			return fmt.Errorf("step %q (type=template): template spec is required", s.ID)
		}
		if s.Packages != nil || s.Service != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			return fmt.Errorf("step %q (type=template): only template may be set", s.ID)
		}
		if err := s.Template.Affirm(); err != nil {
			return fmt.Errorf("step %q: %w", s.ID, err)
		}

	case "service":
		if s.Service == nil {
			return fmt.Errorf("step %q (type=service): service spec is required", s.ID)
		}
		if s.Packages != nil || s.Template != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			return fmt.Errorf("step %q (type=service): only service may be set", s.ID)
		}
		if err := s.Service.Affirm(); err != nil {
			return fmt.Errorf("step %q: %w", s.ID, err)
		}

	case "firewall":
		if s.Firewall == nil {
			return fmt.Errorf("step %q (type=firewall): firewall spec is required", s.ID)
		}
		if s.Packages != nil || s.Template != nil || s.Service != nil || strings.TrimSpace(s.Validate) != "" {
			return fmt.Errorf("step %q (type=firewall): only firewall may be set", s.ID)
		}
		if err := s.Firewall.Affirm(); err != nil {
			return fmt.Errorf("step %q: %w", s.ID, err)
		}

	case "validate":
		if s.Packages != nil || s.Template != nil || s.Service != nil || s.Firewall != nil {
			return fmt.Errorf("step %q (type=validate): no other specs may be set", s.ID)
		}
		kind := strings.ToLower(strings.TrimSpace(s.Validate))
		if kind == "" {
			return fmt.Errorf("step %q (type=validate): validate string is required", s.ID)
		}
		switch kind {
		case "sshd", "firewall":
		default:
			return fmt.Errorf("step %q (type=validate): unsupported validate kind %q (only sshd or firewall are supported)", s.ID, s.Validate)
		}
	}

	return nil
}

func (af ActionFile) Affirm() error {
	if af.Path != "" {
		logger.Debugf("profile: validating action file %q with %d steps", af.Path, len(af.Steps))
	} else {
		logger.Debugf("profile: validating action file with %d steps", len(af.Steps))
	}

	if len(af.Steps) == 0 {
		if af.Path != "" {
			return fmt.Errorf("action file %q: must contain at least one step", af.Path)
		}
		return fmt.Errorf("action file: must contain at least one step")
	}

	for _, step := range af.Steps {
		if err := step.Affirm(); err != nil {
			if af.Path != "" {
				return fmt.Errorf("action file %q: %w", af.Path, err)
			}
			return err
		}
	}

	return nil
}
