package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "schema.json")
	writeSchema(path, struct {
		Name string `json:"name"`
	}{}, nil)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected schema output")
	}
}

func TestGenerateSchemas(t *testing.T) {
	dir := t.TempDir()
	profilePath := filepath.Join(dir, "profile.schema.json")
	actionPath := filepath.Join(dir, "action-file.schema.json")

	generateSchemas(profilePath, actionPath)

	actionSchema := readSchemaObject(t, actionPath)
	defs, ok := actionSchema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("expected $defs object, got %#v", actionSchema["$defs"])
	}
	stepDef, ok := defs["Step"].(map[string]any)
	if !ok {
		t.Fatalf("expected Step schema, got %#v", defs["Step"])
	}
	props, ok := stepDef["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected step properties, got %#v", stepDef["properties"])
	}
	if _, ok := props["config"]; !ok {
		t.Fatalf("expected action step schema to include config, got %#v", props)
	}

	profileSchema := readSchemaObject(t, profilePath)
	if _, ok := profileSchema["$defs"]; !ok {
		t.Fatalf("expected profile schema definitions, got %#v", profileSchema)
	}
}

func TestWriteSchemaPanicsOnInvalidPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected writeSchema to panic on invalid path")
		}
	}()

	writeSchema(filepath.Join(blocker, "schema.json"), struct {
		Name string `json:"name"`
	}{}, nil)
}

func TestWriteSchemaPanicsWhenCreateFails(t *testing.T) {
	dir := t.TempDir()

	defer func() {
		if recover() == nil {
			t.Fatal("expected writeSchema to panic when create fails")
		}
	}()

	writeSchema(dir, struct {
		Name string `json:"name"`
	}{}, nil)
}

func TestMainWritesDefaultSchemas(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	}()

	main()

	for _, path := range []string{
		filepath.Join("schema", "profile.schema.json"),
		filepath.Join("schema", "action-file.schema.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected generated schema %q: %v", path, err)
		}
	}
}

func readSchemaObject(t *testing.T, path string) map[string]any {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %q: %v", path, err)
	}

	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode schema %q: %v", path, err)
	}
	return out
}

func TestApplyPluginConfigConstraints(t *testing.T) {
	schema := map[string]any{"$defs": map[string]any{"Step": map[string]any{}}}
	applyPluginConfigConstraints(schema)

	step := schema["$defs"].(map[string]any)["Step"].(map[string]any)
	branches, ok := step["allOf"].([]any)
	if !ok || len(branches) != len(pluginConfigConstraints) {
		t.Fatalf("expected one branch per constrained plugin, got %#v", step["allOf"])
	}

	var names []string
	for _, b := range branches {
		cond := b.(map[string]any)["if"].(map[string]any)
		names = append(names, cond["properties"].(map[string]any)["plugin"].(map[string]any)["const"].(string))
	}
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Fatalf("branches must be sorted so regeneration is byte-stable, got %v", names)
		}
	}
}

func TestApplyPluginConfigConstraintsPanicsOnUnexpectedSchema(t *testing.T) {
	for _, bad := range []map[string]any{
		{},
		{"$defs": map[string]any{}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected a panic for %#v", bad)
				}
			}()
			applyPluginConfigConstraints(bad)
		}()
	}
}
