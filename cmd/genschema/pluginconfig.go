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
	// A Debian package name, as policy defines it: lower case, digits, plus,
	// minus and period. Each package plugin states its own rule rather than
	// every backend inheriting the union of all of them.
	debNamePattern = `^[a-z0-9][a-z0-9+.-]{0,127}$`
	// An rpm package name, optionally arch-qualified ("glibc.i686"). Wider than
	// the Debian rule: rpm names are case-sensitive and use underscores.
	rpmNamePattern = `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`
	// An octal file mode, with or without the leading zero, capped at four
	// digits so it cannot exceed the 07777 the plugins parse.
	fileModePattern = `^[0-7]{3,4}$`
)

func boolean() map[string]any {
	return map[string]any{"type": "boolean"}
}

func stringPattern(pattern string) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern}
}

// stringEnum is used where the safe set is small enough to list. A value that
// selects which root command runs, or which file that command appends to, gets
// an enum rather than a pattern.
func stringEnum(values ...string) map[string]any {
	items := make([]any, len(values))
	for i, v := range values {
		items[i] = v
	}
	return map[string]any{"type": "string", "enum": items}
}

func stringArrayPattern(pattern string) map[string]any {
	return map[string]any{"type": "array", "items": stringPattern(pattern)}
}

// pluginConfigConstraints maps a plugin name to the properties its config must
// satisfy. Absent properties are unconstrained, so a plugin only appears here
// once it interpolates profile input into a root command.
var pluginConfigConstraints = map[string]map[string]any{
	"service": {
		"name":           stringPattern(serviceUnitPattern),
		"enabled":        boolean(),
		"state":          stringEnum("started", "stopped", "restarted", "reloaded", "reload-or-restart"),
		"restart_policy": restartPolicyConfig(),
	},
	"file_meta": {
		"path":        stringPattern(targetPathPattern),
		"mode":        stringPattern(fileModePattern),
		"owner":       stringPattern(userGroupPattern),
		"group":       stringPattern(userGroupPattern),
		"immutable":   boolean(),
		"append_only": boolean(),
	},
	"template": {
		"src":  stringPattern(profileRelPattern),
		"dest": stringPattern(managedPathPattern),
		"mode": stringPattern(fileModePattern),
	},
	"audit": {
		"src":  stringPattern(profileRelPattern),
		"dest": stringPattern(managedPathPattern),
		"mode": stringPattern(fileModePattern),
	},
	"firewall": {
		"managed_dest": stringPattern(managedPathPattern),
		"main_config":  stringEnum(nftablesMainConfigs...),
	},
	"firewall_template": {
		"managed_dest": stringPattern(managedPathPattern),
		"main_config":  stringEnum(nftablesMainConfigs...),
	},
	// One entry per package plugin. The backend is the plugin, not a config
	// key, so each states the naming rule its own package manager enforces.
	"packages_apt":  packageConfig(debNamePattern),
	"packages_dnf4": packageConfig(rpmNamePattern),
	"packages_dnf5": packageConfig(rpmNamePattern),
}

// restartPolicyConfig is the service plugin's whole restart-policy surface. The
// steps it watches are checked against the profile's step graph at verify, so
// only their shape is stated here.
func restartPolicyConfig() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"type":  stringEnum("always", "on_change"),
			"steps": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
		"required": []any{"type"},
	}
}

// An operation cadence, as the plugins parse it.
const opModePattern = `^(never|always|once|if_[1-9][0-9]*[hdw]_since_last)$`

// packageConfig is the whole config surface of a package plugin, which is
// small enough to state completely. Listing every key is what lets the schema
// close the object below, so a step still carrying the removed "backend" key is
// rejected at verify rather than silently ignored on the host.
func packageConfig(namePattern string) map[string]any {
	return map[string]any{
		"update":     stringPattern(opModePattern),
		"upgrade":    stringPattern(opModePattern),
		"autoremove": stringPattern(opModePattern),
		"install":    stringArrayPattern(namePattern),
		"purge":      stringArrayPattern(namePattern),
		// The collateral a purge is allowed to take. A purge resolves outwards, so
		// the transaction is routinely larger than the list that asked for it; apply
		// refuses any removal named in neither key.
		"purge_also_removes": stringArrayPattern(namePattern),
	}
}

// pluginConfigClosed lists the plugins whose config surface is fully described
// above, so anything else in the object is a mistake worth failing on.
var pluginConfigClosed = map[string]bool{
	"audit":         true,
	"file_meta":     true,
	"packages_apt":  true,
	"packages_dnf4": true,
	"packages_dnf5": true,
	"service":       true,
	"template":      true,
}

// nftablesMainConfigs are the only files apply will append an include to:
// Debian-family and RHEL-family locations of the nftables service config.
var nftablesMainConfigs = []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"}

// pluginConfigRequired lists the config keys a plugin cannot run without. They
// select which root command runs or which file it writes to, so an omission is
// rejected at verify rather than after hardline has connected to the host.
var pluginConfigRequired = map[string][]string{
	"firewall":          {"main_config"},
	"firewall_template": {"main_config"},
	"audit":             {"src", "dest", "mode"},
	"template":          {"src", "dest", "mode"},
	"service":           {"name"},
	"file_meta":         {"path"},
}

func configSchema(plugin string) map[string]any {
	config := map[string]any{"properties": pluginConfigConstraints[plugin]}
	if pluginConfigClosed[plugin] {
		config["additionalProperties"] = false
	}
	if required, ok := pluginConfigRequired[plugin]; ok {
		keys := make([]any, len(required))
		for i, key := range required {
			keys[i] = key
		}
		config["required"] = keys
	}
	return config
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
			// config is required as well as constrained: a "then" that only
			// describes the property leaves a step with no config at all
			// valid, which defers the failure until after hardline has
			// connected to the host.
			"then": map[string]any{
				"properties": map[string]any{
					"config": configSchema(name),
				},
				"required": []any{"config"},
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
