package audit

import (
	"fmt"
	"sort"
	"strings"
)

// A rule key only says a rule with that label exists. Two rules can carry the
// same key and watch entirely different things, so verifying by key alone lets
// a policy that does not match the profile report as loaded. These types carry
// the rule body, which is what the kernel is actually running.

// Rule is one audit rule in a form that can be compared across the two
// spellings it appears in: a rules file writes it one way, and auditctl -l
// prints it back another.
type Rule struct {
	// Watch is the path of a -w rule; empty for a syscall rule.
	Watch string
	// Perms are the -p flags of a watch rule, sorted.
	Perms string
	// List is the "always,exit" half of a syscall rule.
	List string
	// Syscalls are the -S names of a syscall rule, sorted and split, because
	// a file may write "-S a,b" where auditctl prints "-S a -S b".
	Syscalls []string
	// Fields are the -F comparisons other than the key, sorted: auditctl does
	// not preserve the order they were written in.
	Fields []string
	// Key is the rule label, written -k in a file and printed -F key= for a
	// syscall rule by auditctl.
	Key string
}

// Canonical is the comparable form of a rule. Two rules with the same canonical
// string are the same rule however they were spelled.
func (r Rule) Canonical() string {
	if r.Watch != "" {
		return fmt.Sprintf("w|%s|%s|%s", r.Watch, r.Perms, r.Key)
	}
	return fmt.Sprintf("a|%s|%s|%s|%s", r.List, strings.Join(r.Syscalls, ","), strings.Join(r.Fields, ","), r.Key)
}

// String renders a rule the way a rules file writes it, for error messages that
// have to name which rule is missing.
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

// ControlLine reports whether a line configures the audit subsystem rather than
// adding a rule: -D deletes every rule on the host, -e sets the enabled state,
// and the rest are buffer and rate settings. They are not rules, so they are
// not compared, but two of them are refused outright by the preflight.
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

// ParseRules turns a rules file, or auditctl -l output, into comparable rules.
// Anything it cannot parse is returned as an error rather than skipped: a rule
// silently dropped here is a rule nothing would ever verify.
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

// ParseLoadedRules turns auditctl -l output into comparable rules. The running
// policy carries whatever else the host loaded, so a rule this parser cannot
// model is skipped rather than failing the step: it belongs to another owner
// and is never compared. The skipped lines are returned so the caller can say
// what it ignored.
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
			// auditctl prints a syscall rule's key as an ordinary field, so it
			// is lifted back out rather than compared as one.
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
	// A watch written without -p runs with auditctl's default, which is what
	// auditctl then prints back.
	if rule.Watch != "" && rule.Perms == "" {
		rule.Perms = sortedLetters("rwxa")
	}
	return rule, nil
}

// foldWatchFields turns the expanded spelling of a file watch back into the -w
// form. A watch is equally legal written as a syscall rule carrying path= and
// perm=, and which of the two auditctl -l prints depends on its version, so
// both have to land on the same canonical rule.
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
	// Any other comparison makes it a rule a -w watch cannot express, so it
	// stays a syscall rule.
	if watch == "" || len(rest) > 0 {
		return rule
	}

	rule.Watch = normalizeWatchPath(watch)
	rule.Perms = perms
	rule.List = ""
	rule.Fields = nil
	return rule
}

// normalizeWatchPath drops the trailing separator a rules file may write on a
// directory watch. auditctl -l prints the path without it, and both name the
// same directory.
func normalizeWatchPath(watch string) string {
	if trimmed := strings.TrimRight(watch, "/"); trimmed != "" {
		return trimmed
	}
	return watch
}

// idFields are the comparisons whose "no login id" sentinel auditctl re-spells.
// A rules file writes 4294967295, audit 3.x prints unset, and older builds
// print -1; all three are the same value.
var idFields = map[string]struct{}{
	"auid": {}, "uid": {}, "euid": {}, "suid": {}, "fsuid": {},
	"gid": {}, "egid": {}, "sgid": {}, "fsgid": {},
	"obj_uid": {}, "obj_gid": {},
}

// fieldOps are auditctl's comparison operators, longest first so that != is not
// read as =.
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

// MissingRules reports which of want the running policy does not carry, by rule
// body rather than by key. Extra rules in loaded are another owner's business.
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

// WatchPaths is the set of paths a rules file watches, in file order. A watch
// on a path that does not exist makes the whole load fail, so they are checked
// before anything is written.
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

// AssertLoadableRules refuses a managed rules file that would take the host's
// audit policy away from anything else that owns part of it, or that would put
// the policy beyond this run's ability to undo it.
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
