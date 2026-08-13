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

func Keywords() []string {
	out := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		out = append(out, kw.canonical)
	}
	sort.Strings(out)
	return out
}

type Setting struct {
	Keyword string
	Value   string
}

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

func EffectiveKey(keyword string) string {
	return strings.ToLower(keyword)
}

func ParseEffective(out string) map[string][]string {
	effective := make(map[string][]string, 64)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, found := strings.Cut(trimmed, " ")
		if !found {
			effective[strings.ToLower(key)] = append(effective[strings.ToLower(key)], "")
			continue
		}
		key = strings.ToLower(key)
		effective[key] = append(effective[key], strings.TrimSpace(value))
	}
	return effective
}

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
