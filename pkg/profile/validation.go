package profile

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
)

const (
	colorError = "\033[31m"
	colorInfo  = "\033[38;5;15m"
	colorOK    = "\033[38;5;82m"
	colorReset = "\033[0m"
)

type ValidationError struct {
	Issues []string
}

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return colorError + "validation failed with no details" + colorReset
	}
	if len(e.Issues) == 1 {
		return colorError + e.Issues[0] + colorReset
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n%d validation issues:\n", len(e.Issues))
	for _, msg := range e.Issues {
		fmt.Fprintf(&b, " - %s\n", msg)
	}
	return colorError + strings.TrimRight(b.String(), "\n") + colorReset
}

func mergeIssues(parent *[]string, prefix string, err error) {
	if err == nil {
		return
	}
	if v, ok := err.(*ValidationError); ok {
		for _, msg := range v.Issues {
			if prefix != "" {
				*parent = append(*parent, fmt.Sprintf("%s: %s", prefix, msg))
			} else {
				*parent = append(*parent, msg)
			}
		}
		return
	}
	if prefix != "" {
		*parent = append(*parent, fmt.Sprintf("%s: %s", prefix, err.Error()))
	} else {
		*parent = append(*parent, err.Error())
	}
}

func (o OSInfo) Affirm() error {
	logger.Debugf("profile: validating os info: family=%q version=%q variant=%q", o.Family, o.Version, o.Variant)

	var issues []string

	if strings.TrimSpace(o.Family) == "" {
		issues = append(issues, "os.family is required")
	}
	if strings.TrimSpace(o.Version) == "" {
		issues = append(issues, "os.version is required")
	}
	if strings.TrimSpace(o.Variant) == "" {
		issues = append(issues, "os.variant is required")
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (p *Profile) Affirm() error {
	logger.Debugf("profile: validating profile id=%q display_name=%q version=%q schema=%d actions=%d templates=%d",
		p.ID, p.DisplayName, p.Version, p.ProfileSchema, len(p.Actions), len(p.Templates))

	totalSteps := 0
	for _, af := range p.ActionFiles {
		totalSteps += len(af.Steps)
	}

	logger.Infof(colorInfo+"profile %s: %d actions, %d templates, %d steps"+colorReset,
		p.ID, len(p.Actions), len(p.Templates), totalSteps,
	)

	var issues []string

	if strings.TrimSpace(p.ID) == "" {
		issues = append(issues, "profile.id is required")
	}
	if strings.TrimSpace(p.DisplayName) == "" {
		issues = append(issues, "profile.display_name is required")
	}
	if strings.TrimSpace(p.Version) == "" {
		issues = append(issues, "profile.version is required")
	}
	if p.ProfileSchema <= 0 {
		issues = append(issues, "profile.profile_schema must be >= 1")
	}
	if strings.TrimSpace(p.MinHardline) == "" {
		issues = append(issues, "profile.min_hardline is required")
	}
	if len(p.Actions) == 0 {
		issues = append(issues, "profile.actions must contain at least one action file")
	}

	mergeIssues(&issues, "profile.os", p.OS.Affirm())

	if len(p.ActionFiles) != len(p.Actions) {
		issues = append(issues, fmt.Sprintf("profile.ActionFiles not fully loaded (expected %d, have %d)", len(p.Actions), len(p.ActionFiles)))
	} else {
		for _, af := range p.ActionFiles {
			label := "action file"
			if af.Path != "" {
				label = fmt.Sprintf("action file %q", af.Path)
			}
			mergeIssues(&issues, label, af.Affirm())
		}
	}

	if len(issues) == 0 {
		logger.Debugf("profile: validation completed successfully for profile id=%q", p.ID)
		logger.Infof(colorOK+"profile %s: validation OK"+colorReset, p.ID)
		return nil
	}

	return &ValidationError{Issues: issues}
}

func (pk PackageSpec) Affirm() error {
	logger.Debugf("profile: validating packages spec: update=%v upgrade=%v autoremove=%v install=%d purge=%d",
		pk.Update, pk.Upgrade, pk.Autoremove, len(pk.Install), len(pk.Purge))

	var issues []string

	if !pk.Update && !pk.Upgrade && !pk.Autoremove && len(pk.Install) == 0 && len(pk.Purge) == 0 {
		issues = append(issues, "packages step must specify at least one of update/upgrade/autoremove/install/purge")
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (t TemplateSpec) Affirm() error {
	logger.Debugf("profile: validating template spec: src=%q dest=%q mode=%q", t.Src, t.Dest, t.Mode)

	var issues []string

	if strings.TrimSpace(t.Src) == "" {
		issues = append(issues, "template.src is required")
	}
	if strings.TrimSpace(t.Dest) == "" {
		issues = append(issues, "template.dest is required")
	}
	if t.Dest != "" && !filepath.IsAbs(t.Dest) {
		issues = append(issues, fmt.Sprintf("template.dest %q must be an absolute path", t.Dest))
	}
	if strings.TrimSpace(t.Mode) == "" {
		issues = append(issues, "template.mode is required")
	} else {
		var parsed uint64
		if _, err := fmt.Sscanf(t.Mode, "%o", &parsed); err != nil {
			issues = append(issues, fmt.Sprintf("template.mode %q is not valid octal: %v", t.Mode, err))
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (s ServiceSpec) Affirm() error {
	logger.Debugf("profile: validating service spec: name=%q enabled=%v state=%q", s.Name, s.Enabled, s.State)

	var issues []string

	if strings.TrimSpace(s.Name) == "" {
		issues = append(issues, "service.name is required")
	}

	state := strings.TrimSpace(s.State)
	if state != "" {
		switch state {
		case "started", "stopped", "restarted", "reloaded":
			logger.Debugf("profile: service spec: state %q accepted", state)
		default:
			issues = append(issues, fmt.Sprintf("service.state %q is invalid (must be started, stopped, restarted, or reloaded)", s.State))
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (r FirewallRule) Affirm() error {
	logger.Debugf("profile: validating firewall rule: port=%d proto=%q", r.Port, r.Proto)

	var issues []string

	if r.Port <= 0 || r.Port > 65535 {
		issues = append(issues, fmt.Sprintf("firewall rule port %d out of range (1-65535)", r.Port))
	}
	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	switch proto {
	case "tcp", "udp":
		logger.Debugf("profile: firewall rule: proto %q accepted", proto)
	default:
		issues = append(issues, fmt.Sprintf("firewall rule proto %q invalid (must be tcp or udp)", r.Proto))
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (f FirewallSpec) Affirm() error {
	logger.Debugf("profile: validating firewall spec: backend=%q policy=%q template_src=%q template_dest=%q allow_rules=%d",
		f.Backend, f.Policy, f.TemplateSrc, f.TemplateDest, len(f.Allow))

	var issues []string

	switch f.Backend {
	case "nftables":
		logger.Debugf("profile: firewall spec: backend %q accepted", f.Backend)
	case "ufw", "iptables", "firewalld":
		issues = append(issues, fmt.Sprintf("firewall.backend %q is not supported (only nftables is currently supported)", f.Backend))
	default:
		issues = append(issues, fmt.Sprintf("firewall.backend %q is invalid (must be nftables)", f.Backend))
	}

	switch f.Policy {
	case "allow", "deny", "reject", "drop":
		logger.Debugf("profile: firewall spec: policy %q accepted", f.Policy)
	default:
		issues = append(issues, fmt.Sprintf("firewall.policy %q is invalid (must be allow, deny, reject, or drop)", f.Policy))
	}

	if f.TemplateDest != "" && !filepath.IsAbs(f.TemplateDest) {
		issues = append(issues, fmt.Sprintf("firewall.template_dest %q must be an absolute path if set", f.TemplateDest))
	}

	for i, rule := range f.Allow {
		mergeIssues(&issues, fmt.Sprintf("firewall.allow[%d]", i), rule.Affirm())
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (s Step) Affirm() error {
	logger.Debugf("profile: validating step id=%q type=%q severity=%q risk_class=%q", s.ID, s.Type, s.Severity, s.RiskClass)

	var issues []string

	if strings.TrimSpace(s.ID) == "" {
		issues = append(issues, "step.id is required")
	}

	stepType := strings.ToLower(strings.TrimSpace(s.Type))
	switch stepType {
	case "packages", "template", "service", "firewall", "validate":
		logger.Debugf("profile: step %q: type %q accepted", s.ID, stepType)
	default:
		issues = append(issues, fmt.Sprintf("step %q: invalid type %q", s.ID, s.Type))
	}

	switch s.Severity {
	case "low", "medium", "high", "critical":
		logger.Debugf("Severity: step %q: type %q accepted", s.ID, s.Severity)
	default:
		issues = append(issues, fmt.Sprintf("step %q: invalid severity %q", s.ID, s.Severity))
	}

	switch s.RiskClass {
	case "none", "access", "availability", "data_loss", "integrity", "compliance", "other":
		logger.Debugf("risk_class: step %q: type %q accepted", s.ID, s.RiskClass)
	default:
		issues = append(issues, fmt.Sprintf("step %q: invalid risk_class %q", s.ID, s.RiskClass))
	}

	switch stepType {
	case "packages":
		if s.Packages == nil {
			issues = append(issues, fmt.Sprintf("step %q (type=packages): packages spec is required", s.ID))
		}
		if s.Template != nil || s.Service != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			issues = append(issues, fmt.Sprintf("step %q (type=packages): only packages may be set", s.ID))
		}
		if s.Packages != nil {
			mergeIssues(&issues, fmt.Sprintf("step %q", s.ID), s.Packages.Affirm())
		}

	case "template":
		if s.Template == nil {
			issues = append(issues, fmt.Sprintf("step %q (type=template): template spec is required", s.ID))
		}
		if s.Packages != nil || s.Service != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			issues = append(issues, fmt.Sprintf("step %q (type=template): only template may be set", s.ID))
		}
		if s.Template != nil {
			mergeIssues(&issues, fmt.Sprintf("step %q", s.ID), s.Template.Affirm())
		}

	case "service":
		if s.Service == nil {
			issues = append(issues, fmt.Sprintf("step %q (type=service): service spec is required", s.ID))
		}
		if s.Packages != nil || s.Template != nil || s.Firewall != nil || strings.TrimSpace(s.Validate) != "" {
			issues = append(issues, fmt.Sprintf("step %q (type=service): only service may be set", s.ID))
		}
		if s.Service != nil {
			mergeIssues(&issues, fmt.Sprintf("step %q", s.ID), s.Service.Affirm())
		}

	case "firewall":
		if s.Firewall == nil {
			issues = append(issues, fmt.Sprintf("step %q (type=firewall): firewall spec is required", s.ID))
		}
		if s.Packages != nil || s.Template != nil || s.Service != nil || strings.TrimSpace(s.Validate) != "" {
			issues = append(issues, fmt.Sprintf("step %q (type=firewall): only firewall may be set", s.ID))
		}
		if s.Firewall != nil {
			mergeIssues(&issues, fmt.Sprintf("step %q", s.ID), s.Firewall.Affirm())
		}

	case "validate":
		if s.Packages != nil || s.Template != nil || s.Service != nil || s.Firewall != nil {
			issues = append(issues, fmt.Sprintf("step %q (type=validate): no other specs may be set", s.ID))
		}
		kind := strings.ToLower(strings.TrimSpace(s.Validate))
		if kind == "" {
			issues = append(issues, fmt.Sprintf("step %q (type=validate): validate string is required", s.ID))
		} else {
			switch kind {
			case "sshd", "firewall":
				logger.Debugf("profile: step %q (validate): kind %q accepted", s.ID, kind)
			default:
				issues = append(issues, fmt.Sprintf("step %q (type=validate): unsupported validate kind %q (only sshd or firewall are supported)", s.ID, s.Validate))
			}
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}

func (af ActionFile) Affirm() error {
	if af.Path != "" {
		logger.Debugf("profile: validating action file %q with %d steps", af.Path, len(af.Steps))
	} else {
		logger.Debugf("profile: validating action file with %d steps", len(af.Steps))
	}

	var issues []string

	if len(af.Steps) == 0 {
		if af.Path != "" {
			issues = append(issues, fmt.Sprintf("action file %q: must contain at least one step", af.Path))
		} else {
			issues = append(issues, "action file: must contain at least one step")
		}
	} else {
		for idx, step := range af.Steps {
			label := fmt.Sprintf("step[%d] id=%q", idx, step.ID)
			mergeIssues(&issues, label, step.Affirm())
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return &ValidationError{Issues: issues}
}
