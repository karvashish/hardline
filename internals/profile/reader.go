package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Profile struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	OS            string   `json:"os"`
	ProfileSchema int      `json:"profile_schema"`
	MinHardline   string   `json:"min_hardline"`
	Actions       []string `json:"actions"`
	Templates     []string `json:"templates"`

	profilePath string `json:"-"`
}

type PackageSpec struct {
	Update  bool     `json:"update"`
	Upgrade bool     `json:"upgrade"`
	Install []string `json:"install"`
	Purge   []string `json:"purge"`
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

type SysctlSpec struct {
	Set map[string]string `json:"set"`
}

type FirewallRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

type FirewallSpec struct {
	Backend string         `json:"backend"`
	Policy  string         `json:"policy"`
	Allow   []FirewallRule `json:"allow,omitempty"`
}

type Step struct {
	Packages *PackageSpec  `json:"packages,omitempty"`
	Template *TemplateSpec `json:"template,omitempty"`
	Service  *ServiceSpec  `json:"service,omitempty"`
	Sysctl   *SysctlSpec   `json:"sysctl,omitempty"`
	Firewall *FirewallSpec `json:"firewall,omitempty"`
}

type ActionFile struct {
	Steps []Step `json:"steps"`
	Path  string `json:"-"`
}

func Load(dir string) (*Profile, error) {
	if dir == "" {
		dir = "profile"
	}

	path := filepath.Join(dir, "profile.json")

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open profile.json: %w", err)
	}
	defer f.Close()

	var p Profile
	if err := json.NewDecoder(f).Decode(&p); err != nil {
		return nil, fmt.Errorf("decode profile.json: %w", err)
	}

	p.profilePath = dir
	return &p, nil
}

func (p *Profile) ActionPaths() []string {
	out := make([]string, 0, len(p.Actions))
	for _, rel := range p.Actions {
		out = append(out, filepath.Join(p.profilePath, rel))
	}
	return out
}

func (p *Profile) TemplatePaths() []string {
	out := make([]string, 0, len(p.Templates))
	for _, rel := range p.Templates {
		out = append(out, filepath.Join(p.profilePath, rel))
	}
	return out
}

func (p *Profile) LoadActions() ([]ActionFile, error) {
	paths := p.ActionPaths()
	result := make([]ActionFile, 0, len(paths))

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open action file %q: %w", path, err)
		}

		var af ActionFile
		if err := json.NewDecoder(f).Decode(&af); err != nil {
			f.Close()
			return nil, fmt.Errorf("decode action file %q: %w", path, err)
		}
		f.Close()

		af.Path = path
		result = append(result, af)
	}

	return result, nil
}

func (p *Profile) LoadTemplate(rel string) ([]byte, error) {
	path := filepath.Join(p.profilePath, rel)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %q: %w", path, err)
	}
	return b, nil
}
