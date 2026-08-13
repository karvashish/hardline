package main

import "github.com/karvashish/hardline/internals/plugins/ssh"

const (
	serviceUnitPattern = `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`
	managedPathPattern = `^[A-Za-z0-9._/-]+$`
	targetPathPattern  = `^[A-Za-z0-9._/@-]+$`
	userGroupPattern   = `^[A-Za-z0-9._][A-Za-z0-9._-]{0,31}$`
	profileRelPattern  = `^(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+)(?:/(?:[A-Za-z0-9_-][A-Za-z0-9._-]*|[.][A-Za-z0-9_-][A-Za-z0-9._-]*|[.][.][A-Za-z0-9._-]+))*$`
	debNamePattern     = `^[a-z0-9][a-z0-9+.-]{0,127}$`
	rpmNamePattern     = `^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`
	fileModePattern    = `^[0-7]{3,4}$`
)

func boolean() map[string]any {
	return map[string]any{"type": "boolean"}
}

func stringPattern(pattern string) map[string]any {
	return map[string]any{"type": "string", "pattern": pattern}
}

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
		"backend":      stringEnum("nftables"),
		"family":       stringEnum("inet", "ip", "ip6"),
		"table":        stringPattern(nftIdentifierPattern),
		"policies":     firewallPolicies(),
		"rules":        firewallRules(),
	},
	"firewall_template": {
		"managed_dest":  stringPattern(managedPathPattern),
		"main_config":   stringEnum(nftablesMainConfigs...),
		"backend":       stringEnum("nftables"),
		"policy":        stringEnum("allow", "deny", "reject", "drop"),
		"template_src":  stringPattern(profileRelPattern),
		"template_dest": stringPattern(managedPathPattern),
		"allow":         firewallTemplateAllow(),
	},
	"ssh": {
		"path":            stringPattern(managedPathPattern),
		"mode":            stringPattern(fileModePattern),
		"service":         stringEnum("ssh", "sshd"),
		"settings":        sshSettings(),
		"verify_contexts": sshVerifyContexts(),
	},
	"packages_apt":  packageConfig(debNamePattern),
	"packages_dnf4": packageConfig(rpmNamePattern),
	"packages_dnf5": packageConfig(rpmNamePattern),
}

const (
	nftIdentifierPattern = `^[A-Za-z_][A-Za-z0-9_]{0,63}$`
	interfaceNamePattern = `^$|^[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}$`
	addressPattern       = `^$|^[0-9A-Fa-f:.]{1,45}(/[0-9]{1,3})?$`
)

func portNumber() map[string]any {
	return map[string]any{"type": "integer", "minimum": 1, "maximum": 65535}
}

func optionalPortNumber() map[string]any {
	return map[string]any{"type": "integer", "minimum": 0, "maximum": 65535}
}

func firewallPolicies() map[string]any {
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"chain", "policy"},
			"properties": map[string]any{
				"chain":  stringEnum("input", "output", "forward"),
				"policy": stringEnum("accept", "drop"),
			},
		},
	}
}

func firewallRules() map[string]any {
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"chain", "action"},
			"properties": map[string]any{
				"chain":         stringEnum("input", "output", "forward"),
				"action":        stringEnum("accept", "drop", "reject"),
				"proto":         stringEnum("", "tcp", "udp", "icmp", "icmpv6"),
				"port":          optionalPortNumber(),
				"ports":         map[string]any{"type": "array", "items": portNumber()},
				"source":        stringPattern(addressPattern),
				"destination":   stringPattern(addressPattern),
				"in_interface":  stringPattern(interfaceNamePattern),
				"out_interface": stringPattern(interfaceNamePattern),
				"ct_states": map[string]any{
					"type":  "array",
					"items": stringEnum("new", "established", "related", "invalid", "untracked"),
				},
			},
		},
	}
}

func firewallTemplateAllow() map[string]any {
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"port", "proto"},
			"properties": map[string]any{
				"port":  portNumber(),
				"proto": stringEnum("tcp", "udp"),
			},
		},
	}
}

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

const opModePattern = `^(never|always|once|if_[1-9][0-9]*[hdw]_since_last)$`

func packageConfig(namePattern string) map[string]any {
	return map[string]any{
		"update":             stringPattern(opModePattern),
		"upgrade":            stringPattern(opModePattern),
		"autoremove":         stringPattern(opModePattern),
		"install":            stringArrayPattern(namePattern),
		"purge":              stringArrayPattern(namePattern),
		"purge_also_removes": stringArrayPattern(namePattern),
	}
}

var pluginConfigClosed = map[string]bool{
	"audit":             true,
	"file_meta":         true,
	"firewall":          true,
	"firewall_template": true,
	"packages_apt":      true,
	"packages_dnf4":     true,
	"packages_dnf5":     true,
	"service":           true,
	"ssh":               true,
	"template":          true,
}

var nftablesMainConfigs = []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"}

var pluginConfigRequired = map[string][]string{
	"firewall":          {"main_config"},
	"firewall_template": {"main_config"},
	"audit":             {"src", "dest", "mode"},
	"template":          {"src", "dest", "mode"},
	"service":           {"name"},
	"file_meta":         {"path"},
	"ssh":               {"path", "mode", "service", "settings"},
}

func sshSettings() map[string]any {
	names := ssh.Keywords()
	allowed := make([]any, len(names))
	for i, name := range names {
		allowed[i] = name
	}
	return map[string]any{
		"type":          "object",
		"minProperties": 1,
		"propertyNames": map[string]any{"enum": allowed},
		"additionalProperties": map[string]any{
			"oneOf": []any{
				map[string]any{"type": "string", "maxLength": 64},
				map[string]any{"type": "integer"},
			},
		},
	}
}

func sshVerifyContexts() map[string]any {
	field := stringPattern(`^[A-Za-z0-9._:-]{1,255}$`)
	return map[string]any{
		"type": "array",
		"items": map[string]any{
			"type":                 "object",
			"additionalProperties": false,
			"required":             []any{"user", "host", "addr"},
			"properties": map[string]any{
				"user": field,
				"host": field,
				"addr": field,
			},
		},
	}
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
