package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultOverridesFilename is the single auto-discovered overrides file inside a
// profile directory (analogous to terraform.tfvars). When --overrides-file is
// set, that path wins instead.
const DefaultOverridesFilename = "profile.overrides.json"

// ResolveOverrides loads runtime overrides for the given command. When
// --overrides-file is set, only that file is read. Otherwise, if
// <profile>/profile.overrides.json exists, it is loaded automatically.
func ResolveOverrides(c Command) (map[string]json.RawMessage, error) {
	if explicit := strings.TrimSpace(c.OverridesFile); explicit != "" {
		return loadOverridesFile(explicit)
	}

	profileDir := strings.TrimSpace(c.Profile)
	if profileDir == "" {
		return nil, nil
	}

	autoPath := filepath.Join(profileDir, DefaultOverridesFilename)
	values, err := loadOverridesFile(autoPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return values, err
}

func loadOverridesFile(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read overrides file %q: %w", path, err)
	}

	var overrides map[string]json.RawMessage
	if err := json.Unmarshal(data, &overrides); err != nil {
		return nil, fmt.Errorf("decode overrides file %q: %w", path, err)
	}
	if overrides == nil {
		return nil, fmt.Errorf("decode overrides file %q: expected JSON object", path)
	}
	return overrides, nil
}
