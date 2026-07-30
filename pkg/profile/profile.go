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
	// id becomes a directory component of the remote journal path, and
	// actions/templates entries are read as signed content, so both are
	// pattern-bound here to fail a hostile profile at verify. resolve()
	// still enforces the ".." and symlink rules a pattern cannot express.
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

// resolve turns a profile-supplied reference into an absolute path that is
// provably inside the profile directory. The signature covers only files under
// profilePath, so a reference that escapes - through an absolute path, a ..
// segment, or a symlinked subdirectory - would be read unsigned and mutable by
// anyone who can write to the target. A reference that does not exist yet is
// returned as-is; the caller's read reports the missing file.
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

	full := filepath.Join(p.profilePath, filepath.FromSlash(clean))

	resolvedDir, err := filepath.EvalSymlinks(filepath.Dir(full))
	if err != nil {
		return full, nil
	}
	root, err := filepath.EvalSymlinks(p.profilePath)
	if err != nil {
		return "", fmt.Errorf("resolve profile directory %q: %w", p.profilePath, err)
	}
	inside, err := filepath.Rel(root, resolvedDir)
	if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("profile reference %q resolves outside the profile directory", rel)
	}
	return full, nil
}

func (p *Profile) ActionPaths() ([]string, error) {
	out := make([]string, 0, len(p.Actions))
	for _, rel := range p.Actions {
		full, err := p.resolve(rel)
		if err != nil {
			return nil, fmt.Errorf("profile action %w", err)
		}
		out = append(out, full)
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
	paths, err := p.ActionPaths()
	if err != nil {
		return err
	}
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

	full, err := p.resolve(rel)
	if err != nil {
		return nil, fmt.Errorf("profile template %w", err)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("read template %q: %w", full, err)
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
