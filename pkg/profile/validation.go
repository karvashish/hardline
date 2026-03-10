package profile

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	"github.com/google/jsonschema-go/jsonschema"
)

var (
	resolveProfileSchemaPath    = func() string { return schemaPath("profile.schema.json") }
	resolveActionFileSchemaPath = func() string { return schemaPath("action-file.schema.json") }
)

func (p *Profile) Affirm() error {
	if p.profilePath == "" {
		return fmt.Errorf("profile path is empty; load profile before validation")
	}

	profileJSONPath := p.abs("profile.json")
	profileSchema, err := loadResolvedSchema(resolveProfileSchemaPath())
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

	var actionSchema *jsonschema.Resolved
	for _, rel := range manifest.Actions {
		if actionSchema == nil {
			actionSchema, err = loadResolvedSchema(resolveActionFileSchemaPath())
			if err != nil {
				return err
			}
		}

		actionPath := p.abs(rel)
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

func loadResolvedSchema(path string) (*jsonschema.Resolved, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: abs}

	loader := func(uri *url.URL) (*jsonschema.Schema, error) {
		data, err := os.ReadFile(uri.Path)
		if err != nil {
			return nil, err
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, err
		}
		return &s, nil
	}

	schema, err := loader(u)
	if err != nil {
		return nil, err
	}

	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: loader})
	if err != nil {
		return nil, err
	}
	return resolved, nil
}

func readJSONInstance(path string, label string) ([]byte, any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s %q: %w", label, path, err)
	}

	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return nil, nil, fmt.Errorf("decode %s %q: %w", label, path, err)
	}
	return data, instance, nil
}

func schemaPath(name string) string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("schema", name)
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "schema", name)
}
