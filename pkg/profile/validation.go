package profile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"path"

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

func jsonInstance(data []byte, label string, ref string) (any, error) {
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, fmt.Errorf("decode %s %q: %w", label, ref, err)
	}
	return instance, nil
}
