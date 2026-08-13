package audit

import (
	"fmt"
	"sort"
	"strings"
)

type Rule struct {
	Watch    string
	Perms    string
	List     string
	Syscalls []string
	Fields   []string
	Key      string
}

func (r Rule) Canonical() string {
	if r.Watch != "" {
		return fmt.Sprintf("w|%s|%s|%s", r.Watch, r.Perms, r.Key)
	}
	return fmt.Sprintf("a|%s|%s|%s|%s", r.List, strings.Join(r.Syscalls, ","), strings.Join(r.Fields, ","), r.Key)
}

func (r Rule) String() string {
	if r.Watch != "" {
		out := "-w " + r.Watch
		if r.Perms != "" {
			out += " -p " + r.Perms
		}
		if r.Key != "" {
			out += " -k " + r.Key
		}
		return out
	}

	parts := []string{"-a", r.List}
	for _, field := range r.Fields {
		parts = append(parts, "-F", field)
	}
	for _, syscall := range r.Syscalls {
		parts = append(parts, "-S", syscall)
	}
	if r.Key != "" {
		parts = append(parts, "-k", r.Key)
	}
	return strings.Join(parts, " ")
}

func ControlLine(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	switch tokens[0] {
	case "-D", "-e", "-b", "-f", "-r", "--reset-lost", "--loginuid-immutable", "--backlog_wait_time":
		return true
	}
	return false
}

func ParseRules(data []byte) ([]Rule, error) {
	var out []Rule
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.Fields(line)
		if ControlLine(tokens) {
			continue
		}
		rule, err := parseRuleTokens(tokens)
		if err != nil {
			return nil, fmt.Errorf("audit rule %q: %w", line, err)
		}
		out = append(out, rule)
	}
	return out, nil
}

func ParseLoadedRules(data []byte) ([]Rule, []string) {
	var out []Rule
	var skipped []string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := strings.Fields(line)
		if ControlLine(tokens) {
			continue
		}
		rule, err := parseRuleTokens(tokens)
		if err != nil {
			skipped = append(skipped, line)
			continue
		}
		out = append(out, rule)
	}
	return out, skipped
}

func parseRuleTokens(tokens []string) (Rule, error) {
	var rule Rule
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		value := ""
		if i+1 < len(tokens) {
			value = tokens[i+1]
		}

		switch token {
		case "-w":
			if value == "" {
				return Rule{}, fmt.Errorf("-w needs a path")
			}
			rule.Watch = normalizeWatchPath(value)
			i++
		case "-p":
			if value == "" {
				return Rule{}, fmt.Errorf("-p needs permissions")
			}
			rule.Perms = sortedLetters(value)
			i++
		case "-a", "-A":
			if value == "" {
				return Rule{}, fmt.Errorf("%s needs a list and action", token)
			}
			rule.List = value
			i++
		case "-S":
			if value == "" {
				return Rule{}, fmt.Errorf("-S needs a syscall")
			}
			rule.Syscalls = append(rule.Syscalls, strings.Split(value, ",")...)
			i++
		case "-k":
			if value == "" {
				return Rule{}, fmt.Errorf("-k needs a key")
			}
			rule.Key = value
			i++
		case "-F":
			if value == "" {
				return Rule{}, fmt.Errorf("-F needs a comparison")
			}
			if name, ok := strings.CutPrefix(value, "key="); ok {
				rule.Key = name
			} else {
				rule.Fields = append(rule.Fields, normalizeField(value))
			}
			i++
		default:
			return Rule{}, fmt.Errorf("unsupported token %q", token)
		}
	}

	if rule.Watch == "" && rule.List == "" {
		return Rule{}, fmt.Errorf("is neither a watch nor a syscall rule")
	}
	sort.Strings(rule.Syscalls)
	sort.Strings(rule.Fields)
	rule = foldWatchFields(rule)
	if rule.Watch != "" && rule.Perms == "" {
		rule.Perms = sortedLetters("rwxa")
	}
	return rule, nil
}

func foldWatchFields(rule Rule) Rule {
	if rule.Watch != "" || len(rule.Syscalls) > 0 || rule.List != "always,exit" {
		return rule
	}

	watch, perms := "", ""
	var rest []string
	for _, field := range rule.Fields {
		switch {
		case strings.HasPrefix(field, "path="):
			watch = strings.TrimPrefix(field, "path=")
		case strings.HasPrefix(field, "dir="):
			watch = strings.TrimPrefix(field, "dir=")
		case strings.HasPrefix(field, "perm="):
			perms = sortedLetters(strings.TrimPrefix(field, "perm="))
		default:
			rest = append(rest, field)
		}
	}
	if watch == "" || len(rest) > 0 {
		return rule
	}

	rule.Watch = normalizeWatchPath(watch)
	rule.Perms = perms
	rule.List = ""
	rule.Fields = nil
	return rule
}

func normalizeWatchPath(watch string) string {
	if trimmed := strings.TrimRight(watch, "/"); trimmed != "" {
		return trimmed
	}
	return watch
}

var idFields = map[string]struct{}{
	"auid": {}, "uid": {}, "euid": {}, "suid": {}, "fsuid": {},
	"gid": {}, "egid": {}, "sgid": {}, "fsgid": {},
	"obj_uid": {}, "obj_gid": {},
}

var fieldOps = []string{"!=", ">=", "<=", "&=", "=", ">", "<", "&"}

func normalizeField(field string) string {
	for _, op := range fieldOps {
		i := strings.Index(field, op)
		if i <= 0 {
			continue
		}
		name, value := field[:i], field[i+len(op):]
		if _, ok := idFields[name]; !ok {
			return field
		}
		switch value {
		case "4294967295", "-1", "unset":
			value = "unset"
		}
		return name + op + value
	}
	return field
}

func sortedLetters(in string) string {
	letters := strings.Split(strings.TrimSpace(in), "")
	sort.Strings(letters)
	return strings.Join(letters, "")
}

func MissingRules(loaded, want []Rule) []Rule {
	have := make(map[string]struct{}, len(loaded))
	for _, rule := range loaded {
		have[rule.Canonical()] = struct{}{}
	}

	var missing []Rule
	for _, rule := range want {
		if _, ok := have[rule.Canonical()]; !ok {
			missing = append(missing, rule)
		}
	}
	return missing
}

func WatchPaths(rules []Rule) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, rule := range rules {
		if rule.Watch == "" {
			continue
		}
		if _, dup := seen[rule.Watch]; dup {
			continue
		}
		seen[rule.Watch] = struct{}{}
		out = append(out, rule.Watch)
	}
	return out
}

func AssertLoadableRules(data []byte) error {
	for _, raw := range strings.Split(string(data), "\n") {
		tokens := strings.Fields(strings.TrimSpace(raw))
		if len(tokens) == 0 || strings.HasPrefix(tokens[0], "#") {
			continue
		}
		switch tokens[0] {
		case "-D":
			return fmt.Errorf("audit rules contain %q, which deletes every rule on the host, including rules this profile does not own", "-D")
		case "-e":
			if len(tokens) > 1 && tokens[1] == "2" {
				return fmt.Errorf("audit rules contain %q, which locks the policy until the host reboots and leaves this run unable to roll itself back", "-e 2")
			}
		}
	}
	return nil
}
