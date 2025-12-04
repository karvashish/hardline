package profile

//go:generate go run github.com/karvashish/hardline/cmd/genschema

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/karvashish/hardline/pkg/logger"
)

type OSInfo struct {
	Family  string `json:"family"`
	Version string `json:"version"`
	Variant string `json:"variant"`
}

type Profile struct {
	ID            string   `json:"id"`
	DisplayName   string   `json:"display_name"`
	Version       string   `json:"version"`
	OS            OSInfo   `json:"os"`
	ProfileSchema int      `json:"profile_schema" jsonschema:"default=1"`
	MinHardline   string   `json:"min_hardline"`
	Actions       []string `json:"actions"`
	Templates     []string `json:"templates"`

	profilePath string       `json:"-"`
	ActionFiles []ActionFile `json:"-"`
}

type PackageSpec struct {
	Update     bool     `json:"update"`
	Upgrade    bool     `json:"upgrade"`
	Autoremove bool     `json:"autoremove"`
	Install    []string `json:"install"`
	Purge      []string `json:"purge"`
}

type TemplateSpec struct {
	Src  string `json:"src"`
	Dest string `json:"dest"`
	Mode string `json:"mode"`
}

type ServiceSpec struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty" jsonschema:"default=true"`
	State   string `json:"state,omitempty" jsonschema:"enum=started,enum=stopped,enum=restarted,enum=reloaded"`
}

type FirewallRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto" jsonschema:"enum=tcp,enum=udp"`
}

type FirewallSpec struct {
	Backend      string         `json:"backend" jsonschema:"enum=ufw,enum=iptables,enum=nftables,enum=firewalld"`
	Policy       string         `json:"policy" jsonschema:"enum=allow,enum=deny,enum=reject,enum=drop"`
	TemplateSrc  string         `json:"template_src,omitempty"`
	TemplateDest string         `json:"template_dest,omitempty"`
	Allow        []FirewallRule `json:"allow,omitempty"`
}

type Step struct {
	ID          string        `json:"id"`
	Type        string        `json:"type" jsonschema:"enum=packages,enum=template,enum=service,enum=firewall,enum=validate"`
	Severity    string        `json:"severity" jsonschema:"enum=low,enum=medium,enum=high,enum=critical,default=medium"`
	RiskClass   string        `json:"risk_class" jsonschema:"enum=none,enum=access,enum=availability,enum=data_loss,enum=integrity,enum=compliance,enum=other,default=none" jsonschema_description:"Class of possible worst-case consequence if the step fails or is misconfigured (e.g. losing SSH access, outage/availability issue, data loss, or compliance breach)."`
	ControlTags []string      `json:"control_tags"`
	Packages    *PackageSpec  `json:"packages,omitempty"`
	Template    *TemplateSpec `json:"template,omitempty"`
	Service     *ServiceSpec  `json:"service,omitempty"`
	Firewall    *FirewallSpec `json:"firewall,omitempty"`
	Validate    string        `json:"validate,omitempty"`
}

type ActionFile struct {
	Steps []Step `json:"steps"`
	Path  string `json:"-"`
}

func Load(dir string) (*Profile, error) {
	logger.Debugf("profile.Load: dir=%q\n", dir)

	if dir == "" {
		return nil, fmt.Errorf("decode profile.json: profile not found")
	}

	profileJSON := filepath.Join(dir, "profile.json")

	f, err := os.Open(profileJSON)
	if err != nil {
		return nil, fmt.Errorf("open profile.json: %w", err)
	}
	defer f.Close()

	var p Profile
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode profile.json: %w", err)
	}

	p.profilePath = dir

	logger.Debugf(
		"profile.Load: loaded profile id=%q actions=%d templates=%d\n",
		p.ID, len(p.Actions), len(p.Templates),
	)

	if err := p.loadActions(); err != nil {
		return nil, err
	}

	return &p, nil
}

func (p *Profile) abs(rel string) string {
	return filepath.Join(p.profilePath, rel)
}

func (p *Profile) ActionPaths() []string {
	out := make([]string, 0, len(p.Actions))
	for _, rel := range p.Actions {
		out = append(out, p.abs(rel))
	}
	return out
}

func (p *Profile) isDeclaredTemplate(rel string) bool {
	for _, t := range p.Templates {
		if t == rel {
			return true
		}
	}
	return false
}

func (p *Profile) loadActions() error {
	paths := p.ActionPaths()
	result := make([]ActionFile, 0, len(paths))

	logger.Debugf("profile.loadActions: %d action paths\n", len(paths))

	for _, path := range paths {
		logger.Debugf("profile.loadActions: opening action file %q\n", path)

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open action file %q: %w", path, err)
		}

		var af ActionFile
		if err := json.NewDecoder(f).Decode(&af); err != nil {
			f.Close()
			return fmt.Errorf("decode action file %q: %w", path, err)
		}
		f.Close()

		logger.Debugf("profile.loadActions: action file %q has %d steps\n", path, len(af.Steps))

		for _, step := range af.Steps {
			if step.Template != nil {
				if !p.isDeclaredTemplate(step.Template.Src) {
					return fmt.Errorf("action file %q: step %q uses undeclared template %q", path, step.ID, step.Template.Src)
				}
			}
			if step.Firewall != nil && step.Firewall.TemplateSrc != "" {
				if !p.isDeclaredTemplate(step.Firewall.TemplateSrc) {
					return fmt.Errorf("action file %q: step %q uses undeclared firewall template %q", path, step.ID, step.Firewall.TemplateSrc)
				}
			}
		}

		af.Path = path
		result = append(result, af)
	}

	p.ActionFiles = result
	logger.Debugf("profile.loadActions: loaded %d action files\n", len(p.ActionFiles))
	return nil
}

func (p *Profile) LoadTemplate(rel string) ([]byte, error) {
	logger.Debugf("profile.LoadTemplate: rel=%q\n", rel)

	if !p.isDeclaredTemplate(rel) {
		return nil, fmt.Errorf("template %q not declared in profile.json", rel)
	}

	path := p.abs(rel)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %q: %w", path, err)
	}
	return b, nil
}
