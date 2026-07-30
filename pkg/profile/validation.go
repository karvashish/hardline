package profile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"

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

func (p *Profile) Affirm() error {
	if p.profilePath == "" {
		return fmt.Errorf("profile path is empty; load profile before validation")
	}

	profileJSONPath := filepath.Join(p.profilePath, "profile.json")
	profileSchema, err := loadResolvedSchema(profileSchemaName)
	if err != nil {
		return err
	}
	profileData, profileInstance, err := readJSONInstance(profileJSONPath, "profile json")
	if err != nil {
		return err
	}
	if err := profileSchema.Validate(profileInstance); err != nil {
		return fmt.Errorf("profile validation failed: %w", err)
	}

	var manifest Profile
	if err := json.Unmarshal(profileData, &manifest); err != nil {
		return fmt.Errorf("decode profile json %q: %w", profileJSONPath, err)
	}
	if err := manifest.validateAllowedOverrides(); err != nil {
		return err
	}

	var actionSchema *jsonschema.Resolved
	for _, rel := range manifest.Actions {
		if actionSchema == nil {
			actionSchema, err = loadResolvedSchema(actionFileSchemaName)
			if err != nil {
				return err
			}
		}

		actionPath, err := p.resolve(rel)
		if err != nil {
			return fmt.Errorf("profile action %w", err)
		}
		_, actionInstance, err := readJSONInstance(actionPath, "action file")
		if err != nil {
			return err
		}
		if err := actionSchema.Validate(actionInstance); err != nil {
			return fmt.Errorf("action file validation failed for %q: %w", actionPath, err)
		}
	}

	return nil
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

func readJSONInstance(file string, label string) ([]byte, any, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s %q: %w", label, file, err)
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, nil, fmt.Errorf("decode %s %q: %w", label, file, err)
	}
	return data, instance, nil
}
