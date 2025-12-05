package profile

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/jsonschema-go/jsonschema"
)

func (p *Profile) Affirm() any {

	data, err := os.ReadFile("base-secure-ubuntu-24.04-lts/profile.json")
	if err != nil {
		return err
	}
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return err
	}

	abs, err := filepath.Abs("schema/profile.schema.json")
	if err != nil {
		return err
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
		return err
	}

	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{Loader: loader})
	if err != nil {
		return err
	}

	if err := resolved.Validate(instance); err != nil {
		return fmt.Errorf("profile validation failed: %w", err)
	}

	return nil
}
