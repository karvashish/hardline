package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/invopop/jsonschema"
	"github.com/karvashish/hardline/pkg/profile"
)

func writeSchema(path string, v any) {
	r := new(jsonschema.Reflector)
	s := r.Reflect(v)

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
	if err := enc.Encode(s); err != nil {
		panic(err)
	}
}

func main() {
	// schema for profile.json
	writeSchema("schema/profile.schema.json", &profile.Profile{})

	// schema for actions/*.json
	writeSchema("schema/action-file.schema.json", &profile.ActionFile{})
}
