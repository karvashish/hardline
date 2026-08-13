package ssh

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type valueKind int

const (
	kindYesNo valueKind = iota
	kindEnum
	kindInt
)

// keywordSpec is one accepted sshd_config keyword. The set is a whitelist and
// nothing outside it is accepted: a keyword this plugin does not understand is
// one it cannot verify took effect, and an unverifiable hardening claim is
// worse than an absent one.
//
// Port is deliberately absent. Changing it moves the listener to a port the
// host firewall may not accept, and this plugin cannot see the firewall's
// ruleset to tell. Until that coordination exists, the port stays where the
// host has it.
type keywordSpec struct {
	canonical string
	kind      valueKind
	allowed   []string
	min, max  int
}

var keywords = map[string]keywordSpec{
	"allowagentforwarding":         {canonical: "AllowAgentForwarding", kind: kindYesNo},
	"allowtcpforwarding":           {canonical: "AllowTcpForwarding", kind: kindEnum, allowed: []string{"yes", "no", "local", "remote", "all"}},
	"clientalivecountmax":          {canonical: "ClientAliveCountMax", kind: kindInt, min: 0, max: 100},
	"clientaliveinterval":          {canonical: "ClientAliveInterval", kind: kindInt, min: 0, max: 86400},
	"compression":                  {canonical: "Compression", kind: kindEnum, allowed: []string{"yes", "no", "delayed"}},
	"gatewayports":                 {canonical: "GatewayPorts", kind: kindEnum, allowed: []string{"yes", "no", "clientspecified"}},
	"hostbasedauthentication":      {canonical: "HostbasedAuthentication", kind: kindYesNo},
	"ignorerhosts":                 {canonical: "IgnoreRhosts", kind: kindYesNo},
	"kbdinteractiveauthentication": {canonical: "KbdInteractiveAuthentication", kind: kindYesNo},
	"logingracetime":               {canonical: "LoginGraceTime", kind: kindInt, min: 0, max: 3600},
	"loglevel":                     {canonical: "LogLevel", kind: kindEnum, allowed: []string{"QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG", "DEBUG1", "DEBUG2", "DEBUG3"}},
	"maxauthtries":                 {canonical: "MaxAuthTries", kind: kindInt, min: 1, max: 10},
	"maxsessions":                  {canonical: "MaxSessions", kind: kindInt, min: 1, max: 100},
	"passwordauthentication":       {canonical: "PasswordAuthentication", kind: kindYesNo},
	"permitemptypasswords":         {canonical: "PermitEmptyPasswords", kind: kindYesNo},
	"permitrootlogin":              {canonical: "PermitRootLogin", kind: kindEnum, allowed: []string{"yes", "no", "prohibit-password", "forced-commands-only"}},
	"permittunnel":                 {canonical: "PermitTunnel", kind: kindEnum, allowed: []string{"yes", "no", "point-to-point", "ethernet"}},
	"permituserenvironment":        {canonical: "PermitUserEnvironment", kind: kindYesNo},
	"printlastlog":                 {canonical: "PrintLastLog", kind: kindYesNo},
	"pubkeyauthentication":         {canonical: "PubkeyAuthentication", kind: kindYesNo},
	"strictmodes":                  {canonical: "StrictModes", kind: kindYesNo},
	"tcpkeepalive":                 {canonical: "TCPKeepAlive", kind: kindYesNo},
	"usepam":                       {canonical: "UsePAM", kind: kindYesNo},
	"x11forwarding":                {canonical: "X11Forwarding", kind: kindYesNo},
}

// Keywords lists every accepted keyword in canonical spelling. The schema
// generator reads it so the JSON schema and this table cannot drift apart.
func Keywords() []string {
	out := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		out = append(out, kw.canonical)
	}
	sort.Strings(out)
	return out
}

// Setting is one validated keyword and its value in the spelling sshd expects.
type Setting struct {
	Keyword string
	Value   string
}

// ParseSettings validates the declared settings and returns them sorted by
// keyword. Sorting is what makes the rendered file byte-stable: Go map order is
// not, and an unstable render would rewrite the drop-in and reload sshd on
// every run.
func ParseSettings(raw map[string]any) ([]Setting, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("settings must declare at least one keyword")
	}

	seen := make(map[string]string, len(raw))
	out := make([]Setting, 0, len(raw))
	for name, value := range raw {
		spec, ok := keywords[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			return nil, fmt.Errorf("keyword %q is not one this plugin can verify; accepted keywords are %s",
				name, strings.Join(Keywords(), ", "))
		}
		// Two spellings of one keyword would render twice, and sshd would keep
		// whichever sorted first while the profile claims both.
		if other, dup := seen[spec.canonical]; dup {
			return nil, fmt.Errorf("keyword %s is declared twice, as %q and %q", spec.canonical, other, name)
		}
		seen[spec.canonical] = name

		text, err := settingValue(spec, value)
		if err != nil {
			return nil, fmt.Errorf("keyword %s: %w", spec.canonical, err)
		}
		out = append(out, Setting{Keyword: spec.canonical, Value: text})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Keyword < out[j].Keyword })
	return out, nil
}

func settingValue(spec keywordSpec, value any) (string, error) {
	switch spec.kind {
	case kindInt:
		n, err := intValue(value)
		if err != nil {
			return "", err
		}
		if n < spec.min || n > spec.max {
			return "", fmt.Errorf("%d is outside the accepted range %d-%d", n, spec.min, spec.max)
		}
		return strconv.Itoa(n), nil
	case kindYesNo:
		return oneOf(value, []string{"yes", "no"})
	case kindEnum:
		return oneOf(value, spec.allowed)
	default:
		return "", fmt.Errorf("unsupported keyword kind")
	}
}

// intValue accepts a JSON number or its decimal string spelling. encoding/json
// decodes every number into a float64, so a value that is not a whole number
// has to be rejected here rather than truncated into something the profile
// never declared.
func intValue(value any) (int, error) {
	switch v := value.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, fmt.Errorf("%v is not a whole number", v)
		}
		return int(v), nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("%q is not an integer", v)
		}
		return n, nil
	case bool:
		return 0, fmt.Errorf("expected an integer, got a boolean")
	default:
		return 0, fmt.Errorf("expected an integer, got %T", value)
	}
}

// oneOf accepts only a string. A JSON boolean is refused on purpose: YAML-style
// true would render as "true", which sshd does not accept for a yes/no keyword,
// and silently rewriting it to "yes" would accept a profile that does not say
// what its author reads it as saying.
func oneOf(value any, allowed []string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("expected one of %s as a string, got %T", strings.Join(allowed, ", "), value)
	}
	trimmed := strings.TrimSpace(text)
	for _, candidate := range allowed {
		if strings.EqualFold(trimmed, candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%q is not one of %s", text, strings.Join(allowed, ", "))
}

// Render writes the drop-in. The header names the owner so an operator reading
// the file on the host knows what rewrites it.
func Render(settings []Setting) []byte {
	var b strings.Builder
	b.WriteString("# Managed by hardline. Changes here are overwritten.\n")
	for _, s := range settings {
		b.WriteString(s.Keyword)
		b.WriteByte(' ')
		b.WriteString(s.Value)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// EffectiveKey is the name sshd -T prints for a keyword, which is the canonical
// spelling lowercased.
func EffectiveKey(keyword string) string {
	return strings.ToLower(keyword)
}

// ParseEffective reads sshd -T output, which is one "keyword value" per line
// with the keyword lowercased. A keyword may legitimately appear more than once
// (hostkey, subsystem), so values accumulate rather than overwrite.
func ParseEffective(out string) map[string][]string {
	effective := make(map[string][]string, 64)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, " ")
		if !found {
			// A keyword sshd prints with no value carries a real meaning:
			// the option is set to empty. Record it as such.
			effective[strings.ToLower(key)] = append(effective[strings.ToLower(key)], "")
			continue
		}
		key = strings.ToLower(key)
		effective[key] = append(effective[key], strings.TrimSpace(value))
	}
	return effective
}

// DivergentSettings reports every declared keyword the running configuration
// does not actually carry. An absent keyword is a divergence in its own right,
// not a gap to skip: sshd drops directives it no longer implements without
// failing, so "not reported" is exactly how a profile discovers it is asking
// for something this sshd will never honour.
func DivergentSettings(effective map[string][]string, want []Setting) []string {
	var drift []string
	for _, s := range want {
		key := EffectiveKey(s.Keyword)
		values, ok := effective[key]
		if !ok {
			drift = append(drift, fmt.Sprintf("%s: sshd does not report this keyword, so it is not a directive this sshd honours", s.Keyword))
			continue
		}
		if len(values) != 1 {
			drift = append(drift, fmt.Sprintf("%s: sshd reports %d values (%s) where one was declared", s.Keyword, len(values), strings.Join(values, ", ")))
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(values[0]), s.Value) {
			drift = append(drift, fmt.Sprintf("%s: effective value is %q but the profile declares %q", s.Keyword, values[0], s.Value))
		}
	}
	sort.Strings(drift)
	return drift
}
