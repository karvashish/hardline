package profile

//go:generate go run github.com/karvashish/hardline/cmd/genschema

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
)

type OSInfo struct {
	Family  string `json:"family"`
	Version string `json:"version"`
	Variant string `json:"variant"`
}

type Profile struct {
	ID               string   `json:"id"`
	DisplayName      string   `json:"display_name"`
	Version          string   `json:"version"`
	OS               OSInfo   `json:"os"`
	ProfileSchema    int      `json:"profile_schema" jsonschema:"default=1"`
	MinHardline      string   `json:"min_hardline"`
	Actions          []string `json:"actions"`
	Templates        []string `json:"templates"`
	AllowedOverrides []string `json:"allowed_overrides,omitempty" jsonschema:"pattern=^[a-z][a-z0-9_]*$"`

	profilePath      string                     `json:"-"`
	ActionFiles      []ActionFile               `json:"-"`
	runtimeOverrides map[string]json.RawMessage `json:"-"`
}

type Step struct {
	ID               string         `json:"id"`
	Plugin           string         `json:"plugin"`
	Config           map[string]any `json:"config,omitempty"`
	AllowUnvalidated bool           `json:"allow_unvalidated,omitempty"`
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

func (s Step) PluginName() string {
	return strings.ToLower(strings.TrimSpace(s.Plugin))
}

func (s Step) Decode(dst any) error {
	payload := s.Config
	if payload == nil {
		payload = map[string]any{}
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("step %q (%s): encode step config: %w", s.ID, s.PluginName(), err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("step %q (%s): decode step config: %w", s.ID, s.PluginName(), err)
	}
	return nil
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

func (p *Profile) SetRuntimeOverrides(overrides map[string]json.RawMessage) {
	p.runtimeOverrides = maps.Clone(overrides)
}

func (p *Profile) RuntimeOverrides() map[string]json.RawMessage {
	if p == nil {
		return nil
	}
	return maps.Clone(p.runtimeOverrides)
}

func (p *Profile) ValidateOverrides(overrides map[string]json.RawMessage) error {
	if len(overrides) == 0 {
		return nil
	}

	allowed := make(map[string]struct{}, len(p.AllowedOverrides))
	for _, name := range p.AllowedOverrides {
		allowed[name] = struct{}{}
	}

	var unknown []string
	for key := range overrides {
		if _, ok := allowed[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("profile does not allow overrides: %s", strings.Join(unknown, ", "))
	}
	return nil
}

func (p *Profile) validateAllowedOverrides() error {
	seen := make(map[string]struct{}, len(p.AllowedOverrides))
	for _, name := range p.AllowedOverrides {
		if name == "" {
			return fmt.Errorf("profile allowed_overrides contains an empty name")
		}
		if !allowedOverrideNamePattern.MatchString(name) {
			return fmt.Errorf("profile allowed_overrides contains invalid name %q", name)
		}
		if _, ok := seen[name]; ok {
			return fmt.Errorf("profile allowed_overrides contains duplicate %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

var allowedOverrideNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
