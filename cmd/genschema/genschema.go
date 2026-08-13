package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
	"github.com/karvashish/hardline/pkg/profile"
)

// writeSchema reflects v and writes it out. transform, when set, gets the
// decoded schema so generated constraints the reflector cannot express (the
// per-plugin config rules) can be attached before encoding.
func writeSchema(path string, v any, transform func(map[string]any)) {
	r := new(jsonschema.Reflector)
	s := r.Reflect(v)

	payload := any(s)
	if transform != nil {
		raw, err := json.Marshal(s)
		if err != nil {
			panic(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			panic(err)
		}
		transform(decoded)
		payload = decoded
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}

	f, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		panic(err)
	}
}

func generateSchemas(profileSchemaPath, actionSchemaPath string) {
	writeSchema(profileSchemaPath, &profile.Profile{}, nil)
	writeSchema(actionSchemaPath, &profile.ActionFile{}, applyPluginConfigConstraints)
}

func main() {
	generateSchemas(
		"schema/profile.schema.json",
		"schema/action-file.schema.json",
	)
}
