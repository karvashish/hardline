package main

// Per-plugin config constraints. The reflected Step leaves config freeform, so
// a hostile value in a signed profile would only be caught once a plugin ran,
// after hardline had already connected to the host. These patterns move that
// rejection to verify, and they are the same whitelists the plugins enforce in
// Go: schema and code have to agree, so keep them in sync deliberately.
//
// Only fields that reach a root command are listed. Everything else in a
// plugin's config stays unconstrained here and is validated by the plugin.

const (
	// A systemd unit name, no leading dash so it cannot be read as an option.
	serviceUnitPattern = `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`
	// A managed destination: no $, backtick, parens, quotes, glob or space.
	managedPathPattern = `^[A-Za-z0-9._/-]+$`
	// A file_meta target: as above, plus @ for systemd template unit paths.
	targetPathPattern = `^[A-Za-z0-9._/@-]+$`
	// A user or group name as useradd/groupadd accept it.
	userGroupPattern = `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`
	// A profile-relative reference. Each segment must be a real name, so a
	// leading /, a backslash, and any "." or ".." segment are all excluded and
	// the reference cannot climb out of the signed tree.
	profileRelPattern = `^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+)(?:/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+))*$`
	// A package name.
	packageNamePattern = `^[a-zA-Z0-9][a-zA-Z0-9.+-]*$`
)

func stringPattern(pattern string) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern}
}

func stringArrayPattern(pattern string) map[string]any {
	return map[string]any{"type": "array", "items": stringPattern(pattern)}
}

// pluginConfigConstraints maps a plugin name to the properties its config must
// satisfy. Absent properties are unconstrained, so a plugin only appears here
// once it interpolates profile input into a root command.
var pluginConfigConstraints = map[string]map[string]any{
	"service": {
		"name": stringPattern(serviceUnitPattern),
	},
	"file_meta": {
		"path":  stringPattern(targetPathPattern),
		"owner": stringPattern(userGroupPattern),
		"group": stringPattern(userGroupPattern),
	},
	"template": {
		"src":  stringPattern(profileRelPattern),
		"dest": stringPattern(managedPathPattern),
	},
	"firewall": {
		"managed_dest": stringPattern(managedPathPattern),
	},
	"firewall_template": {
		"managed_dest": stringPattern(managedPathPattern),
	},
	"packages": {
		"install": stringArrayPattern(packageNamePattern),
		"purge":   stringArrayPattern(packageNamePattern),
	},
}

// applyPluginConfigConstraints attaches one if/then per plugin to the Step
// definition of the reflected action-file schema.
func applyPluginConfigConstraints(schema map[string]any) {
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		panic("action-file schema has no $defs")
	}
	step, ok := defs["Step"].(map[string]any)
	if !ok {
		panic("action-file schema has no Step definition")
	}

	branches := make([]any, 0, len(pluginConfigConstraints))
	for _, name := range sortedPluginNames() {
		branches = append(branches, map[string]any{
			"if": map[string]any{
				"properties": map[string]any{"plugin": map[string]any{"const": name}},
				"required":   []any{"plugin"},
			},
			"then": map[string]any{
				"properties": map[string]any{
					"config": map[string]any{"properties": pluginConfigConstraints[name]},
				},
			},
		})
	}
	step["allOf"] = branches
}

func sortedPluginNames() []string {
	names := make([]string, 0, len(pluginConfigConstraints))
	for name := range pluginConfigConstraints {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}
