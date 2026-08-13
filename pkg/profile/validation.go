package profile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"path"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/karvashish/hardline/schema"
)

const (
	profileSchemaName    = "profile.schema.json"
	actionFileSchemaName = "action-file.schema.json"
)

// schemaFS is the embedded schema set. It is a variable only so tests can swap
// in a fixture FS; nothing at runtime replaces it.
var schemaFS fs.FS = schema.FS

// Affirm schema-checks the profile against the same authenticated bytes the
// profile was decoded from. It does not re-read the profile directory: a schema
// pass over content other than what will be applied proves nothing.
func (p *Profile) Affirm() error {
	if p.profilePath == "" {
		return fmt.Errorf("profile path is empty; load profile before validation")
	}

	profileData, ok := p.files[profileFileName]
	if !ok {
		return fmt.Errorf("read profile json: %s is not covered by the signed manifest", profileFileName)
	}

	profileSchema, err := loadResolvedSchema(profileSchemaName)
	if err != nil {
		return err
	}
	profileInstance, err := jsonInstance(profileData, "profile json", profileFileName)
	if err != nil {
		return err
	}
	if err := profileSchema.Validate(profileInstance); err != nil {
		return fmt.Errorf("profile validation failed: %w", err)
	}

	if err := p.validateAllowedOverrides(); err != nil {
		return err
	}

	var actionSchema *jsonschema.Resolved
	for _, rel := range p.Actions {
		if actionSchema == nil {
			actionSchema, err = loadResolvedSchema(actionFileSchemaName)
			if err != nil {
				return err
			}
		}

		content, err := p.signedBytes(rel)
		if err != nil {
			return fmt.Errorf("profile action %w", err)
		}
		actionInstance, err := jsonInstance(content, "action file", rel)
		if err != nil {
			return err
		}
		if err := actionSchema.Validate(actionInstance); err != nil {
			return fmt.Errorf("action file validation failed for %q: %w", rel, err)
		}
	}

	return p.validateStepGraph()
}

// validateStepGraph checks the step list the run will execute: action files in
// declared order, steps in file order. A duplicate ID overwrites the other
// step's entry in the change map and makes the rollback dependency lookup
// ambiguous, and a restart dependency on a step that does not exist, or has not
// run yet, can never register a change - so the restart it was meant to trigger
// silently never happens.
func (p *Profile) validateStepGraph() error {
	position := make(map[string]int, 16)
	order := 0

	for _, af := range p.ActionFiles {
		for i, step := range af.Steps {
			id := strings.TrimSpace(step.ID)
			if id == "" {
				return fmt.Errorf("action file %q: step %d has an empty id", af.Path, i)
			}
			if id != step.ID {
				return fmt.Errorf("action file %q: step id %q must not have leading or trailing whitespace", af.Path, step.ID)
			}
			if _, dup := position[id]; dup {
				return fmt.Errorf("action file %q: step id %q is already declared by an earlier step", af.Path, id)
			}
			position[id] = order
			order++
		}
	}

	order = 0
	for _, af := range p.ActionFiles {
		for _, step := range af.Steps {
			deps, err := step.watchedSteps()
			if err != nil {
				return fmt.Errorf("action file %q: step %q: %w", af.Path, step.ID, err)
			}
			for _, dep := range deps {
				if dep == step.ID {
					return fmt.Errorf("action file %q: step %q watches itself", af.Path, step.ID)
				}
				depOrder, ok := position[dep]
				if !ok {
					return fmt.Errorf("action file %q: step %q watches unknown step %q", af.Path, step.ID, dep)
				}
				if depOrder > order {
					return fmt.Errorf("action file %q: step %q watches step %q, which runs after it", af.Path, step.ID, dep)
				}
			}
			order++
		}
	}
	return nil
}

// watchedSteps returns the step IDs this step's restart policy watches. Only
// the service plugin declares them, and reading its config here is deliberate:
// the graph is a profile-level property, and routing it through a plugin hook
// would buy indirection for a single caller.
func (s Step) watchedSteps() ([]string, error) {
	if s.PluginName() != "service" {
		return nil, nil
	}

	var spec struct {
		RestartPolicy *struct {
			Steps []string `json:"steps"`
		} `json:"restart_policy"`
	}
	if err := s.Decode(&spec); err != nil {
		return nil, err
	}
	if spec.RestartPolicy == nil {
		return nil, nil
	}

	out := make([]string, 0, len(spec.RestartPolicy.Steps))
	for _, dep := range spec.RestartPolicy.Steps {
		trimmed := strings.TrimSpace(dep)
		if trimmed == "" {
			return nil, fmt.Errorf("restart_policy steps contains an empty step id")
		}
		out = append(out, trimmed)
	}
	return out, nil
}

// loadResolvedSchema reads name from the embedded schema FS. $ref targets
// resolve through the same FS, keyed on the base name, so no schema is ever
// read from the filesystem at runtime.
func loadResolvedSchema(name string) (*jsonschema.Resolved, error) {
	loader := func(uri *url.URL) (*jsonschema.Schema, error) {
		base := path.Base(uri.Path)
		data, err := fs.ReadFile(schemaFS, base)
		if err != nil {
			return nil, fmt.Errorf("read embedded schema %q: %w", base, err)
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("decode embedded schema %q: %w", base, err)
		}
		return &s, nil
	}

	root, err := loader(&url.URL{Scheme: "file", Path: name})
	if err != nil {
		return nil, err
	}

	resolved, err := root.Resolve(&jsonschema.ResolveOptions{Loader: loader})
	if err != nil {
		return nil, err
	}
	return resolved, nil
}

func jsonInstance(data []byte, label string, ref string) (any, error) {
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("decode %s %q: %w", label, ref, err)
	}
	return instance, nil
}
