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

// profileFileName is the profile-relative key of the profile manifest itself
// inside the signed snapshot.
const profileFileName = "profile.json"

// OSInfo is the target declaration the runner checks /etc/os-release against.
// Family and Version are pattern-bound so a missing or malformed value cannot
// silently disable either half of the check in a signed profile.
type OSInfo struct {
	Family  string `json:"family" jsonschema:"pattern=^[a-z][a-z0-9._-]*$"`
	Version string `json:"version" jsonschema:"pattern=^[0-9]+(\\.[0-9]+)*$"`
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
	files            map[string][]byte          `json:"-"`
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

// LoadFromBundle decodes a profile out of the byte snapshot the integrity check
// authenticated, keyed by profile-relative path. dir is retained for messages
// only: nothing here opens a file, because a second read of a path whose bytes
// were already signed reads whatever is on disk now rather than what was signed.
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

// resolve turns a profile-supplied reference into the profile-relative key the
// signed snapshot is indexed by. The snapshot covers only files under the
// profile directory, so a reference that escapes - through an absolute path or
// a .. segment - names something the signature never covered, and is rejected
// here rather than looked up and missed.
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

// signedBytes returns the authenticated content for a profile-relative
// reference. A reference the manifest did not cover is an error, not a miss:
// the only way to reach content outside the snapshot is to name it.
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
