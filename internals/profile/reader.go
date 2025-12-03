package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	ProfileSchema int      `json:"profile_schema"`
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
	Enabled *bool  `json:"enabled,omitempty"`
	State   string `json:"state,omitempty"`
}

type FirewallRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

type FirewallSpec struct {
	Backend      string         `json:"backend"`
	Policy       string         `json:"policy"`
	TemplateSrc  string         `json:"template_src,omitempty"`
	TemplateDest string         `json:"template_dest,omitempty"`
	Allow        []FirewallRule `json:"allow,omitempty"`
}

type Step struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Severity    string        `json:"severity"`
	RiskClass   string        `json:"risk_class"`
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

func (p *Profile) loadActions() error {
	paths := p.ActionPaths()
	result := make([]ActionFile, 0, len(paths))

	for _, path := range paths {
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

		af.Path = path
		result = append(result, af)
	}

	p.ActionFiles = result
	return nil
}

func (p *Profile) LoadTemplate(rel string) ([]byte, error) {
	path := p.abs(rel)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %q: %w", path, err)
	}
	return b, nil
}
