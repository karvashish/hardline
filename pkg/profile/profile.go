package profile

//go:generate go run github.com/karvashish/hardline/cmd/genschema

import (
	"encoding/json"
	"fmt"
	"maps"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/karvashish/hardline/pkg/logger"
)

const profileFileName = "profile.json"

type OSInfo struct {
	Family  string `json:"family" jsonschema:"pattern=^[a-z][a-z0-9._-]*$"`
	Version string `json:"version" jsonschema:"pattern=^[0-9]+(\\.[0-9]+)*$"`
	Variant string `json:"variant"`
}

type Profile struct {
	ID               string   `json:"id" jsonschema:"pattern=^[A-Za-z0-9][A-Za-z0-9._-]*$"`
	DisplayName      string   `json:"display_name"`
	Version          string   `json:"version"`
	OS               OSInfo   `json:"os"`
	ProfileSchema    int      `json:"profile_schema" jsonschema:"default=1"`
	MinHardline      string   `json:"min_hardline"`
	Actions          []string `json:"actions" jsonschema:"pattern=^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+)(?:/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+))*$"`
	Templates        []string `json:"templates" jsonschema:"pattern=^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+)(?:/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+))*$"`
	AllowedOverrides []string `json:"allowed_overrides,omitempty" jsonschema:"pattern=^[a-z][a-z0-9_]*$"`

	profilePath      string                     `json:"-"`
	ActionFiles      []ActionFile               `json:"-"`
	files            map[string][]byte          `json:"-"`
	runtimeOverrides map[string]json.RawMessage `json:"-"`
}

type Step struct {
	ID     string         `json:"id"`
	Plugin string         `json:"plugin"`
	Config map[string]any `json:"config,omitempty"`
}

type ActionFile struct {
	Steps []Step `json:"steps"`
	Path  string `json:"-"`
}

func LoadFromBundle(dir string, files map[string][]byte) (*Profile, error) {
	logger.Debugf("profile.LoadFromBundle: dir=%q files=%d\n", dir, len(files))

	if dir == "" {
		return nil, fmt.Errorf("decode profile.json: profile not found")
	}

	profileJSON, ok := files[profileFileName]
	if !ok {
		return nil, fmt.Errorf("decode profile.json: %s is not covered by the signed manifest", profileFileName)
	}

	var p Profile
	if err := json.Unmarshal(profileJSON, &p); err != nil {
		return nil, fmt.Errorf("decode profile.json: %w", err)
	}

	p.profilePath = dir
	p.files = files

	logger.Debugf(
		"profile.LoadFromBundle: loaded profile id=%q actions=%d templates=%d\n",
		p.ID, len(p.Actions), len(p.Templates),
	)

	if err := p.loadActions(); err != nil {
		return nil, err
	}

	return &p, nil
}

func (p *Profile) resolve(rel string) (string, error) {
	clean := filepath.ToSlash(strings.TrimSpace(rel))
	if clean == "" {
		return "", fmt.Errorf("profile reference is empty")
	}
	if strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("profile reference %q must not contain a backslash", rel)
	}
	if strings.HasPrefix(clean, "/") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("profile reference %q must be relative to the profile directory", rel)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", fmt.Errorf("profile reference %q must not contain a %q segment", rel, "..")
		}
	}
	return path.Clean(clean), nil
}

func (p *Profile) signedBytes(rel string) ([]byte, error) {
	key, err := p.resolve(rel)
	if err != nil {
		return nil, err
	}
	content, ok := p.files[key]
	if !ok {
		return nil, fmt.Errorf("profile reference %q is not covered by the signed manifest", rel)
	}
	return content, nil
}

func (p *Profile) ActionPaths() ([]string, error) {
	out := make([]string, 0, len(p.Actions))
	for _, rel := range p.Actions {
		key, err := p.resolve(rel)
		if err != nil {
			return nil, fmt.Errorf("profile action %w", err)
		}
		out = append(out, key)
	}
	return out, nil
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
	result := make([]ActionFile, 0, len(p.Actions))

	logger.Debugf("profile.loadActions: %d action references\n", len(p.Actions))

	for _, rel := range p.Actions {
		content, err := p.signedBytes(rel)
		if err != nil {
			return fmt.Errorf("profile action %w", err)
		}

		var af ActionFile
		if err := json.Unmarshal(content, &af); err != nil {
			return fmt.Errorf("decode action file %q: %w", rel, err)
		}

		logger.Debugf("profile.loadActions: action file %q has %d steps\n", rel, len(af.Steps))

		af.Path = rel
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

	content, err := p.signedBytes(rel)
	if err != nil {
		return nil, fmt.Errorf("profile template %w", err)
	}
	return content, nil
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
