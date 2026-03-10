package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/rollbackutil"
	"github.com/karvashish/hardline/internals/rollback"
	"github.com/karvashish/hardline/pkg/logger"
	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	NftablesMainConfigPath = "/etc/nftables.conf"
	NftablesIncludeLine    = `include "/etc/nftables.d/*.nft"`
	IncludeCheckCmd        = `grep -E -q 'include[[:space:]]+"?/etc/nftables\.d/\*\.nft"?' /etc/nftables.conf`
)

type ApplyDeps struct {
	RunRoot          func(*ssh.Client, string) error
	NewSFTPClient    func(*ssh.Client) (*sftp.Client, error)
	WriteRootFile    func(*ssh.Client, *sftp.Client, string, []byte, os.FileMode) error
	MarkServiceDirty func(string)
}

type RollbackDeps struct {
	RunRoot           func(*ssh.Client, string) error
	RunRootWithOutput func(*ssh.Client, string) (string, error)
	ReadRootFile      func(*ssh.Client, string) (string, error)
}

type NormalizedSpec struct {
	Family   string
	Table    string
	Policies map[string]string
	Rules    []NormalizedRule
}

type NormalizedRule struct {
	Chain        string
	Action       string
	Proto        string
	Port         int
	Source       string
	Destination  string
	InInterface  string
	OutInterface string
	CTStates     []string
}

type NormalizedDiff struct {
	PolicyChanges []string
	RulesToAdd    []NormalizedRule
	RulesToRemove []NormalizedRule
}

func Apply(ctx pluginapi.ApplyContext, fw *Spec, deps ApplyDeps) error {
	logger.Debugf("handleFirewall: backend=%q policies=%d rules=%d\n", fw.Backend, len(fw.Policies), len(fw.Rules))

	if fw.Backend != "nftables" {
		return fmt.Errorf("unsupported firewall backend %q", fw.Backend)
	}

	desired, err := NormalizeDesiredSpec(fw)
	if err != nil {
		return err
	}
	destPath := ManagedDestination(fw)
	if destPath == "" {
		return fmt.Errorf("firewall managed_dest is required")
	}

	dir := path.Dir(destPath)
	if dir != "" && dir != "." {
		if err := deps.RunRoot(ctx.Client, fmt.Sprintf("mkdir -p %q", dir)); err != nil {
			return fmt.Errorf("mkdir -p %s: %w", dir, err)
		}
	}
	if err := EnsureNftablesInclude(ctx.Client, deps.RunRoot); err != nil {
		return err
	}

	sftpClient, err := deps.NewSFTPClient(ctx.Client)
	if err != nil {
		return fmt.Errorf("new sftp client: %w", err)
	}
	if sftpClient != nil {
		defer sftpClient.Close()
	}

	desiredRendered := RenderNormalized(desired)
	if err := deps.WriteRootFile(ctx.Client, sftpClient, destPath, []byte(desiredRendered), os.FileMode(0644)); err != nil {
		return fmt.Errorf("remote.WriteRootFile %s: %w", destPath, err)
	}
	if deps.MarkServiceDirty != nil {
		deps.MarkServiceDirty("nftables")
	}

	logger.Debugf("handleFirewall: rendered deterministic firewall rules to %q\n", destPath)
	return nil
}

func Plan(ctx pluginapi.PlanContext, fw *Spec) (pluginapi.PlanResult, error) {
	logger.Debugf("planFirewall: backend=%q family=%q table=%q policies=%d rules=%d\n", fw.Backend, fw.Family, fw.Table, len(fw.Policies), len(fw.Rules))

	var details []string

	if fw.Backend != "nftables" {
		summary := fmt.Sprintf("firewall step: unsupported backend %q (no-op)", fw.Backend)
		return pluginapi.PlanResult{Summary: summary, Details: []string{"only nftables backend is supported by executor"}, Noop: 2}, nil
	}
	if strings.TrimSpace(fw.Family) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: family is required")
	}
	if strings.TrimSpace(fw.Table) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: table is required")
	}
	if strings.TrimSpace(fw.ManagedDest) == "" {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: managed_dest is required")
	}
	if len(fw.Policies) == 0 {
		return pluginapi.PlanResult{}, fmt.Errorf("firewall step: policies are required")
	}

	info, err := ctx.Inspector.Stat(fw.ManagedDest)
	if err != nil {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("managed destination %q: does not exist (file will be created)", fw.ManagedDest)+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorBlue+fmt.Sprintf("managed destination %q: exists (size=%d mode=%#o)", fw.ManagedDest, info.Size(), info.Mode().Perm())+logger.ColorReset,
		)
	}

	details = append(details, logger.ColorGreen+fmt.Sprintf("desired table: %s %s", fw.Family, fw.Table)+logger.ColorReset)
	details = append(details, logger.ColorGreen+fmt.Sprintf("desired chain policies: %d", len(fw.Policies))+logger.ColorReset)
	details = append(details, logger.ColorGreen+fmt.Sprintf("desired rules: %d", len(fw.Rules))+logger.ColorReset)

	if ctx.Inspector.FirewallIncludePresent() {
		details = append(details, logger.ColorGreen+`nftables.conf include "/etc/nftables.d/*.nft" is present`+logger.ColorReset)
	} else {
		details = append(details, logger.ColorRed+`nftables.conf include "/etc/nftables.d/*.nft" is missing (validate would fail)`+logger.ColorReset)
	}

	summary := fmt.Sprintf(
		"firewall step (deterministic): backend=nftables table=%s %s, managed_dest=%q, policies=%d, rules=%d",
		fw.Family, fw.Table, fw.ManagedDest, len(fw.Policies), len(fw.Rules),
	)
	return pluginapi.PlanResult{Summary: summary, Details: details, Noop: 2}, nil
}

func ValidateApply(ctx pluginapi.ApplyContext, runRoot func(*ssh.Client, string) error) error {
	if err := runRoot(ctx.Client, IncludeCheckCmd); err != nil {
		return fmt.Errorf("nftables.conf missing include for /etc/nftables.d/*.nft: %w", err)
	}

	if err := runRoot(ctx.Client, "nft -c -f /etc/nftables.conf"); err != nil {
		return fmt.Errorf("nftables config check failed: %w", err)
	}
	return nil
}

func ValidatePlan(ctx pluginapi.PlanContext) (pluginapi.PlanResult, error) {
	logger.Debugf("planValidate: kind=firewall\n")

	var details []string

	if ctx.Inspector.FirewallIncludePresent() {
		details = append(details,
			logger.ColorGreen+`nftables.conf: include "/etc/nftables.d/*.nft" is present`+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorRed+`nftables.conf: include "/etc/nftables.d/*.nft" is missing (validate would fail)`+logger.ColorReset,
		)
	}

	testErr := ctx.Inspector.FirewallConfigTest()
	if testErr == nil {
		details = append(details,
			logger.ColorGreen+"current nftables configuration: passes nft -c -f /etc/nftables.conf"+logger.ColorReset,
		)
	} else {
		details = append(details,
			logger.ColorRed+fmt.Sprintf("current nftables configuration: nft -c reports errors (%v)", testErr)+logger.ColorReset,
		)
	}

	return pluginapi.PlanResult{
		Summary: "validate firewall: check include for /etc/nftables.d/*.nft and nft -c on /etc/nftables.conf",
		Details: details,
		Noop:    2,
	}, nil
}

func CaptureRollback(ctx pluginapi.RollbackContext, stepID string, spec *Spec, deps RollbackDeps) (rollback.StepRecord, error) {
	record := rollback.StepRecord{
		ID:   stepID,
		Type: "firewall",
	}
	if spec == nil {
		return record, fmt.Errorf("step %q (type=firewall): firewall spec missing", stepID)
	}

	dest := ManagedDestination(spec)
	if err := rollbackutil.EnforceManagedPath(dest); err != nil {
		return record, fmt.Errorf("step %q (type=firewall): %w", stepID, err)
	}

	snap, err := rollbackutil.SnapshotRemoteFile(ctx.Client, dest, rollbackutil.Deps{
		RunRoot:           deps.RunRoot,
		RunRootWithOutput: deps.RunRootWithOutput,
		ReadRootFile:      deps.ReadRootFile,
	})
	if err != nil {
		return record, fmt.Errorf("capture firewall snapshot for %q: %w", dest, err)
	}

	record.RollbackMode = rollback.ModeDeterministic
	record.Objects = []rollback.ObjectRecord{
		{Kind: rollback.ObjectFile, File: &snap},
	}
	return record, nil
}

func ManagedDestination(fw *Spec) string {
	if fw == nil {
		return ""
	}
	if p := strings.TrimSpace(fw.ManagedDest); p != "" {
		return p
	}
	return ""
}

func EnsureNftablesInclude(client *ssh.Client, runRoot func(*ssh.Client, string) error) error {
	if err := runRoot(client, IncludeCheckCmd); err == nil {
		return nil
	}

	appendCmd := "printf '\\ninclude \"/etc/nftables.d/*.nft\"\\n' >> /etc/nftables.conf"
	if err := runRoot(client, appendCmd); err != nil {
		return fmt.Errorf("ensure %q in %s: %w", NftablesIncludeLine, NftablesMainConfigPath, err)
	}

	if err := runRoot(client, IncludeCheckCmd); err != nil {
		return fmt.Errorf("verify %q in %s: %w", NftablesIncludeLine, NftablesMainConfigPath, err)
	}

	return nil
}

func NormalizeDesiredSpec(fw *Spec) (NormalizedSpec, error) {
	family := normalizeFirewallFamily(fw.Family)
	if family == "" {
		return NormalizedSpec{}, fmt.Errorf("firewall family is required")
	}
	switch family {
	case "inet", "ip", "ip6":
	default:
		return NormalizedSpec{}, fmt.Errorf("unsupported firewall family %q", fw.Family)
	}
	table := normalizeFirewallTable(fw.Table)
	if table == "" {
		return NormalizedSpec{}, fmt.Errorf("firewall table is required")
	}

	out := NormalizedSpec{
		Family:   family,
		Table:    table,
		Policies: make(map[string]string),
	}

	if len(fw.Policies) == 0 {
		return out, fmt.Errorf("firewall policies are required")
	}
	for _, cp := range fw.Policies {
		cn, err := NormalizeChain(cp.Chain)
		if err != nil {
			return out, fmt.Errorf("normalize firewall chain %q: %w", cp.Chain, err)
		}
		if cn == "" {
			return out, fmt.Errorf("normalize firewall chain %q: chain is required", cp.Chain)
		}
		pn, err := NormalizePolicy(cp.Policy)
		if err != nil {
			return out, fmt.Errorf("normalize firewall policy for chain %q: %w", cp.Chain, err)
		}
		out.Policies[cn] = pn
	}

	seen := make(map[string]struct{})
	for idx, rule := range fw.Rules {
		normRules, err := NormalizeDesiredRule(rule)
		if err != nil {
			return out, fmt.Errorf("normalize firewall rule #%d: %w", idx+1, err)
		}
		for _, nr := range normRules {
			key := nr.key()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out.Rules = append(out.Rules, nr)
		}
	}
	for _, rule := range out.Rules {
		if _, ok := out.Policies[rule.Chain]; !ok {
			return out, fmt.Errorf("missing policy for chain %q used by rules", rule.Chain)
		}
	}

	sort.Slice(out.Rules, func(i, j int) bool {
		return out.Rules[i].key() < out.Rules[j].key()
	})
	return out, nil
}

func NormalizeDesiredRule(rule Rule) ([]NormalizedRule, error) {
	chain, err := NormalizeChain(rule.Chain)
	if err != nil {
		return nil, err
	}
	if chain == "" {
		return nil, fmt.Errorf("rule chain is required")
	}

	action := strings.ToLower(strings.TrimSpace(rule.Action))
	if action == "" {
		return nil, fmt.Errorf("rule action is required")
	}
	if action != "accept" && action != "drop" && action != "reject" {
		return nil, fmt.Errorf("unsupported rule action %q", rule.Action)
	}

	proto := strings.ToLower(strings.TrimSpace(rule.Proto))
	switch proto {
	case "", "tcp", "udp", "icmp", "icmpv6":
	default:
		return nil, fmt.Errorf("unsupported rule proto %q", rule.Proto)
	}

	ports := make([]int, 0, len(rule.Ports)+1)
	if rule.Port != 0 {
		ports = append(ports, rule.Port)
	}
	ports = append(ports, rule.Ports...)
	seenPorts := make(map[int]struct{}, len(ports))
	filteredPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("invalid port %d", port)
		}
		if _, ok := seenPorts[port]; ok {
			continue
		}
		seenPorts[port] = struct{}{}
		filteredPorts = append(filteredPorts, port)
	}
	sort.Ints(filteredPorts)

	src := strings.TrimSpace(rule.Source)
	dst := strings.TrimSpace(rule.Destination)
	iif := strings.TrimSpace(rule.InInterface)
	oif := strings.TrimSpace(rule.OutInterface)
	ctStates, err := normalizeCTStates(rule.CTStates)
	if err != nil {
		return nil, err
	}

	switch proto {
	case "tcp", "udp":
		if len(filteredPorts) == 0 {
			return nil, fmt.Errorf("rule proto %q requires port or ports", proto)
		}
	case "icmp", "icmpv6":
		if len(filteredPorts) > 0 {
			return nil, fmt.Errorf("rule proto %q must not define port or ports", proto)
		}
	case "":
		if len(filteredPorts) > 0 {
			return nil, fmt.Errorf("rule with empty proto must not define port or ports")
		}
	}

	hasMatcher := proto != "" || len(ctStates) > 0 || src != "" || dst != "" || iif != "" || oif != ""
	if !hasMatcher {
		return nil, fmt.Errorf("rule must define at least one matcher (proto/ports, ct_states, interfaces, or addresses)")
	}

	if len(filteredPorts) == 0 {
		return []NormalizedRule{{
			Chain:        chain,
			Action:       action,
			Proto:        proto,
			Port:         0,
			Source:       src,
			Destination:  dst,
			InInterface:  iif,
			OutInterface: oif,
			CTStates:     ctStates,
		}}, nil
	}

	out := make([]NormalizedRule, 0, len(filteredPorts))
	for _, port := range filteredPorts {
		out = append(out, NormalizedRule{
			Chain:        chain,
			Action:       action,
			Proto:        proto,
			Port:         port,
			Source:       src,
			Destination:  dst,
			InInterface:  iif,
			OutInterface: oif,
			CTStates:     ctStates,
		})
	}
	return out, nil
}

func normalizeFirewallFamily(family string) string {
	return strings.ToLower(strings.TrimSpace(family))
}

func normalizeFirewallTable(table string) string {
	return strings.TrimSpace(table)
}

func NormalizePolicy(policy string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(policy))
	switch p {
	case "accept":
		return "accept", nil
	case "drop":
		return "drop", nil
	case "reject":
		return "reject", nil
	default:
		return "", fmt.Errorf("unsupported policy %q", policy)
	}
}

func NormalizeChain(chain string) (string, error) {
	c := strings.ToLower(strings.TrimSpace(chain))
	if c == "" {
		return "", fmt.Errorf("chain is required")
	}
	switch c {
	case "input", "output", "forward":
		return c, nil
	default:
		return "", fmt.Errorf("unsupported chain %q", chain)
	}
}

func normalizeCTStates(states []string) ([]string, error) {
	if len(states) == 0 {
		return nil, nil
	}
	allowed := map[string]struct{}{
		"new":         {},
		"established": {},
		"related":     {},
		"invalid":     {},
		"untracked":   {},
	}
	seen := make(map[string]struct{}, len(states))
	out := make([]string, 0, len(states))
	for _, state := range states {
		s := strings.ToLower(strings.TrimSpace(state))
		if s == "" {
			continue
		}
		if _, ok := allowed[s]; !ok {
			return nil, fmt.Errorf("unsupported ct state %q", state)
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

type nftJSONDocument struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

type nftJSONChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Policy string `json:"policy"`
}

type nftJSONRule struct {
	Family string            `json:"family"`
	Table  string            `json:"table"`
	Chain  string            `json:"chain"`
	Expr   []json.RawMessage `json:"expr"`
}

func NormalizeCurrentState(nftJSON, family, table string) (NormalizedSpec, error) {
	out := NormalizedSpec{
		Family:   family,
		Table:    table,
		Policies: make(map[string]string),
	}

	var doc nftJSONDocument
	if err := json.Unmarshal([]byte(nftJSON), &doc); err != nil {
		return out, fmt.Errorf("decode nftables json state: %w", err)
	}

	seenRules := make(map[string]struct{})
	for _, entry := range doc.Nftables {
		if rawChain, ok := entry["chain"]; ok {
			var c nftJSONChain
			if err := json.Unmarshal(rawChain, &c); err == nil {
				if c.Family == family && c.Table == table && strings.TrimSpace(c.Hook) != "" {
					chain, err := NormalizeChain(c.Hook)
					if err == nil && strings.TrimSpace(c.Policy) != "" {
						pol, err := NormalizePolicy(c.Policy)
						if err == nil {
							out.Policies[chain] = pol
						}
					}
				}
			}
		}
		if rawRule, ok := entry["rule"]; ok {
			var r nftJSONRule
			if err := json.Unmarshal(rawRule, &r); err != nil {
				continue
			}
			if r.Family != family || r.Table != table {
				continue
			}
			rules := normalizeNftRuleExpr(r)
			for _, nr := range rules {
				key := nr.key()
				if _, ok := seenRules[key]; ok {
					continue
				}
				seenRules[key] = struct{}{}
				out.Rules = append(out.Rules, nr)
			}
		}
	}

	sort.Slice(out.Rules, func(i, j int) bool {
		return out.Rules[i].key() < out.Rules[j].key()
	})
	return out, nil
}

func normalizeNftRuleExpr(r nftJSONRule) []NormalizedRule {
	chain, err := NormalizeChain(r.Chain)
	if err != nil {
		return nil
	}

	proto := ""
	ports := []int{}
	src := ""
	dst := ""
	iif := ""
	oif := ""
	action := ""
	ctStates := []string{}

	for _, rawExpr := range r.Expr {
		var expr map[string]json.RawMessage
		if err := json.Unmarshal(rawExpr, &expr); err != nil {
			continue
		}

		if _, ok := expr["accept"]; ok {
			action = "accept"
			continue
		}
		if _, ok := expr["drop"]; ok {
			action = "drop"
			continue
		}
		if _, ok := expr["reject"]; ok {
			action = "reject"
			continue
		}

		rawMatch, ok := expr["match"]
		if !ok {
			continue
		}

		var match struct {
			Left  map[string]json.RawMessage `json:"left"`
			Right json.RawMessage            `json:"right"`
		}
		if err := json.Unmarshal(rawMatch, &match); err != nil {
			continue
		}

		if rawPayload, ok := match.Left["payload"]; ok {
			var payload struct {
				Protocol string `json:"protocol"`
				Field    string `json:"field"`
			}
			if err := json.Unmarshal(rawPayload, &payload); err == nil {
				switch {
				case (payload.Protocol == "tcp" || payload.Protocol == "udp") && payload.Field == "dport":
					if p := DecodeNftPortValues(match.Right); len(p) > 0 {
						proto = payload.Protocol
						ports = append(ports, p...)
					}
				case (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "saddr":
					if s := DecodeNftStringValue(match.Right); s != "" {
						src = s
					}
				case (payload.Protocol == "ip" || payload.Protocol == "ip6") && payload.Field == "daddr":
					if s := DecodeNftStringValue(match.Right); s != "" {
						dst = s
					}
				case payload.Protocol == "ip" && payload.Field == "protocol":
					if s := strings.ToLower(strings.TrimSpace(DecodeNftStringValue(match.Right))); s == "icmp" {
						proto = "icmp"
					}
				case payload.Protocol == "ip6" && payload.Field == "nexthdr":
					if s := strings.ToLower(strings.TrimSpace(DecodeNftStringValue(match.Right))); s == "icmpv6" {
						proto = "icmpv6"
					}
				}
			}
		}

		if rawMeta, ok := match.Left["meta"]; ok {
			var meta struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(rawMeta, &meta); err == nil {
				switch meta.Key {
				case "iifname":
					if s := DecodeNftStringValue(match.Right); s != "" {
						iif = s
					}
				case "oifname":
					if s := DecodeNftStringValue(match.Right); s != "" {
						oif = s
					}
				}
			}
		}

		if rawCT, ok := match.Left["ct"]; ok {
			var ct struct {
				Key string `json:"key"`
			}
			if err := json.Unmarshal(rawCT, &ct); err == nil && ct.Key == "state" {
				ctStates = append(ctStates, DecodeNftStringValues(match.Right)...)
			}
		}
	}

	if action == "" {
		return nil
	}

	ctStates, err = normalizeCTStates(ctStates)
	if err != nil {
		return nil
	}

	seenPorts := make(map[int]struct{})
	filteredPorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, ok := seenPorts[port]; ok {
			continue
		}
		seenPorts[port] = struct{}{}
		filteredPorts = append(filteredPorts, port)
	}
	sort.Ints(filteredPorts)

	if len(filteredPorts) > 0 {
		if proto != "tcp" && proto != "udp" {
			return nil
		}
		out := make([]NormalizedRule, 0, len(filteredPorts))
		for _, port := range filteredPorts {
			out = append(out, NormalizedRule{
				Chain:        chain,
				Action:       action,
				Proto:        proto,
				Port:         port,
				Source:       src,
				Destination:  dst,
				InInterface:  iif,
				OutInterface: oif,
				CTStates:     ctStates,
			})
		}
		return out
	}

	if proto == "tcp" || proto == "udp" {
		return nil
	}
	if proto == "" && len(ctStates) == 0 && src == "" && dst == "" && iif == "" && oif == "" {
		return nil
	}
	return []NormalizedRule{{
		Chain:        chain,
		Action:       action,
		Proto:        proto,
		Source:       src,
		Destination:  dst,
		InInterface:  iif,
		OutInterface: oif,
		CTStates:     ctStates,
	}}
}

func DecodeNftPortValues(raw json.RawMessage) []int {
	var anyVal any
	if err := json.Unmarshal(raw, &anyVal); err != nil {
		return nil
	}

	values := []int{}
	appendIfPort := func(v any) {
		switch t := v.(type) {
		case float64:
			n := int(t)
			if float64(n) == t {
				values = append(values, n)
			}
		case string:
			n, err := strconv.Atoi(strings.TrimSpace(t))
			if err == nil {
				values = append(values, n)
			}
		}
	}

	switch t := anyVal.(type) {
	case map[string]any:
		if setVal, ok := t["set"]; ok {
			if arr, ok := setVal.([]any); ok {
				for _, v := range arr {
					appendIfPort(v)
				}
				return values
			}
		}
	case []any:
		for _, v := range t {
			appendIfPort(v)
		}
		return values
	default:
		appendIfPort(anyVal)
		return values
	}

	return values
}

func DecodeNftStringValues(raw json.RawMessage) []string {
	var anyVal any
	if err := json.Unmarshal(raw, &anyVal); err != nil {
		return nil
	}

	values := []string{}
	appendOne := func(v any) {
		switch t := v.(type) {
		case string:
			for _, part := range strings.Split(t, ",") {
				s := strings.ToLower(strings.TrimSpace(part))
				if s != "" {
					values = append(values, s)
				}
			}
		}
	}

	switch t := anyVal.(type) {
	case map[string]any:
		if setVal, ok := t["set"]; ok {
			if arr, ok := setVal.([]any); ok {
				for _, v := range arr {
					appendOne(v)
				}
			}
		}
	case []any:
		for _, v := range t {
			appendOne(v)
		}
	default:
		appendOne(anyVal)
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func DecodeNftStringValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	values := DecodeNftStringValues(raw)
	if len(values) == 1 {
		return values[0]
	}
	return ""
}

func DiffNormalized(current, desired NormalizedSpec) NormalizedDiff {
	diff := NormalizedDiff{}

	managedChains := make(map[string]struct{})
	for chain := range desired.Policies {
		managedChains[chain] = struct{}{}
	}
	for _, rule := range desired.Rules {
		managedChains[rule.Chain] = struct{}{}
	}

	chains := make([]string, 0, len(managedChains))
	for c := range managedChains {
		chains = append(chains, c)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		desiredPolicy := desired.Policies[chain]
		currentPolicy := current.Policies[chain]
		if currentPolicy == "" {
			currentPolicy = "accept"
		}
		if desiredPolicy != currentPolicy {
			diff.PolicyChanges = append(diff.PolicyChanges,
				fmt.Sprintf("chain %s policy: %s -> %s", chain, currentPolicy, desiredPolicy))
		}
	}

	desiredSet := make(map[string]NormalizedRule, len(desired.Rules))
	for _, rule := range desired.Rules {
		desiredSet[rule.key()] = rule
	}
	currentSet := make(map[string]NormalizedRule)
	for _, rule := range current.Rules {
		if _, managed := managedChains[rule.Chain]; !managed {
			continue
		}
		currentSet[rule.key()] = rule
	}

	for key, rule := range desiredSet {
		if _, ok := currentSet[key]; !ok {
			diff.RulesToAdd = append(diff.RulesToAdd, rule)
		}
	}
	for key, rule := range currentSet {
		if _, ok := desiredSet[key]; !ok {
			diff.RulesToRemove = append(diff.RulesToRemove, rule)
		}
	}

	sort.Slice(diff.RulesToAdd, func(i, j int) bool {
		return diff.RulesToAdd[i].key() < diff.RulesToAdd[j].key()
	})
	sort.Slice(diff.RulesToRemove, func(i, j int) bool {
		return diff.RulesToRemove[i].key() < diff.RulesToRemove[j].key()
	})

	return diff
}

func RenderNormalized(spec NormalizedSpec) string {
	managedChains := make(map[string]struct{})
	for chain := range spec.Policies {
		managedChains[chain] = struct{}{}
	}
	for _, rule := range spec.Rules {
		managedChains[rule.Chain] = struct{}{}
	}

	chains := orderedFirewallChains(managedChains)
	var b strings.Builder

	fmt.Fprintf(&b, "table %s %s {\n", spec.Family, spec.Table)
	for _, chain := range chains {
		policy := spec.Policies[chain]
		fmt.Fprintf(&b, "  chain %s {\n", chain)
		fmt.Fprintf(&b, "    type filter hook %s priority 0;\n", chain)
		fmt.Fprintf(&b, "    policy %s;\n\n", policy)

		for _, rule := range spec.Rules {
			if rule.Chain != chain {
				continue
			}
			fmt.Fprintf(&b, "    %s\n", RenderNormalizedRule(spec.Family, rule))
		}
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func orderedFirewallChains(set map[string]struct{}) []string {
	preferred := []string{"input", "forward", "output"}
	seen := make(map[string]struct{}, len(set))
	out := make([]string, 0, len(set))
	for _, chain := range preferred {
		if _, ok := set[chain]; ok {
			out = append(out, chain)
			seen[chain] = struct{}{}
		}
	}
	var rest []string
	for chain := range set {
		if _, ok := seen[chain]; ok {
			continue
		}
		rest = append(rest, chain)
	}
	sort.Strings(rest)
	out = append(out, rest...)
	return out
}

func RenderNormalizedRule(family string, r NormalizedRule) string {
	parts := make([]string, 0, 10)
	if r.InInterface != "" {
		parts = append(parts, fmt.Sprintf(`iif "%s"`, r.InInterface))
	}
	if r.OutInterface != "" {
		parts = append(parts, fmt.Sprintf(`oif "%s"`, r.OutInterface))
	}

	srcKey := "ip"
	if family == "ip6" {
		srcKey = "ip6"
	}
	if r.Source != "" {
		parts = append(parts, fmt.Sprintf("%s saddr %s", srcKey, r.Source))
	}
	if r.Destination != "" {
		parts = append(parts, fmt.Sprintf("%s daddr %s", srcKey, r.Destination))
	}

	if len(r.CTStates) > 0 {
		parts = append(parts, "ct state "+strings.Join(r.CTStates, ","))
	}

	switch r.Proto {
	case "tcp", "udp":
		parts = append(parts, fmt.Sprintf("%s dport %d", r.Proto, r.Port))
	case "icmp":
		parts = append(parts, "ip protocol icmp")
	case "icmpv6":
		parts = append(parts, "ip6 nexthdr icmpv6")
	}
	parts = append(parts, r.Action)
	return strings.Join(parts, " ")
}

func (r NormalizedRule) Key() string {
	return r.key()
}

func (r NormalizedRule) key() string {
	return strings.Join([]string{
		r.Chain,
		r.Action,
		r.Proto,
		strconv.Itoa(r.Port),
		r.Source,
		r.Destination,
		r.InInterface,
		r.OutInterface,
		strings.Join(r.CTStates, ","),
	}, "|")
}
