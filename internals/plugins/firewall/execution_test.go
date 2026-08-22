package firewall

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"os"
	"path"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	testMainConfig = MainConfigDebian
	testDest       = "/etc/nftables.d/99-hardline-firewall.nft"
)

var (
	testIncludeCheck    = includeCheckCmd(testMainConfig, testDest)
	testLegacyGlobCheck = includeCheckCmd(testMainConfig, path.Dir(testDest)+"/*.nft")
)

func TestNormalizeDesiredSpec(t *testing.T) {
	spec, err := NormalizeDesiredSpec(&Spec{
		Backend:     "nftables",
		MainConfig:  testMainConfig,
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []Policy{
			{Chain: "input", Policy: "drop"},
			{Chain: "output", Policy: "accept"},
		},
		Rules: []Rule{
			{Chain: "input", Proto: "tcp", Port: 22, Source: "10.0.0.0/24", InInterface: "eth0", Action: "accept"},
			{Chain: "input", Proto: "tcp", Port: 443, Action: "accept"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeDesiredSpec failed: %v", err)
	}
	if spec.Family != "inet" || spec.Table != "filter" {
		t.Fatalf("unexpected family/table: %+v", spec)
	}
	if spec.Policies["input"] != "drop" || spec.Policies["output"] != "accept" {
		t.Fatalf("unexpected policies: %#v", spec.Policies)
	}
	if len(spec.Rules) != 2 {
		t.Fatalf("expected 2 normalized rules, got %d", len(spec.Rules))
	}
}

func TestNormalizeCurrentState(t *testing.T) {
	nftJSON := `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"eth0"}},
      {"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":"10.0.0.0/24"}},
      {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":{"set":[22,443]}}},
      {"accept":null}
    ]}}
  ]
}`
	state, err := NormalizeCurrentState(nftJSON, "inet", "filter")
	if err != nil {
		t.Fatalf("NormalizeCurrentState failed: %v", err)
	}
	if state.Policies["input"] != "drop" {
		t.Fatalf("expected input policy drop, got %#v", state.Policies)
	}
	if len(state.Rules) != 2 {
		t.Fatalf("expected 2 rules from set dport expression, got %d", len(state.Rules))
	}
	for _, rule := range state.Rules {
		if rule.InInterface != "eth0" || rule.Source != "10.0.0.0/24" || rule.Proto != "tcp" || rule.Action != "accept" {
			t.Fatalf("unexpected normalized rule: %+v", rule)
		}
	}

	_, err = NormalizeCurrentState("{", "inet", "filter")
	if err == nil || !strings.Contains(err.Error(), "decode nftables json state") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

func TestDiffRenderAndKeyHelpers(t *testing.T) {
	current := NormalizedSpec{
		Family:   "inet",
		Table:    "filter",
		Policies: map[string]string{"input": "accept", "forward": "drop"},
		Rules: []NormalizedRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 22},
			{Chain: "forward", Action: "drop", Proto: "tcp", Port: 1},
		},
	}
	desired := NormalizedSpec{
		Family:   "inet",
		Table:    "filter",
		Policies: map[string]string{"input": "drop"},
		Rules: []NormalizedRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 443},
		},
	}

	diff := DiffNormalized(current, desired)
	if len(diff.PolicyChanges) != 1 {
		t.Fatalf("expected one policy change, got %#v", diff.PolicyChanges)
	}
	if len(diff.RulesToAdd) != 1 || diff.RulesToAdd[0].Port != 443 {
		t.Fatalf("unexpected add diff: %#v", diff.RulesToAdd)
	}
	if len(diff.RulesToRemove) != 1 || diff.RulesToRemove[0].Port != 22 {
		t.Fatalf("unexpected remove diff: %#v", diff.RulesToRemove)
	}

	rendered := RenderNormalized(desired)
	if !strings.Contains(rendered, "table inet filter") || !strings.Contains(rendered, "policy drop") || !strings.Contains(rendered, "tcp dport 443 accept") {
		t.Fatalf("unexpected rendered output: %q", rendered)
	}

	ordered := orderedFirewallChains(map[string]struct{}{"z": {}, "input": {}, "output": {}})
	if strings.Join(ordered, ",") != "input,output,z" {
		t.Fatalf("unexpected chain order: %v", ordered)
	}

	line := RenderNormalizedRule("ip6", NormalizedRule{Proto: "tcp", Port: 443, Action: "accept", Source: "2001:db8::/64", Destination: "2001:db8::1/128", InInterface: "eth0", OutInterface: "eth1"})
	for _, want := range []string{`iif "eth0"`, `oif "eth1"`, "ip6 saddr 2001:db8::/64", "ip6 daddr 2001:db8::1/128", "tcp dport 443", "accept"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in rendered rule %q", want, line)
		}
	}

	rule := NormalizedRule{Chain: "input", Action: "accept", Proto: "tcp", Port: 22}
	if rule.key() == "" {
		t.Fatalf("expected non-empty rule key")
	}
}

func TestNormalizeRuleAndDecodeHelpers(t *testing.T) {
	if _, err := NormalizePolicy("allow"); err == nil {
		t.Fatalf("expected invalid policy error")
	}
	if _, err := NormalizeChain("weird"); err == nil {
		t.Fatalf("expected invalid chain error")
	}

	if normalizeFirewallFamily(" INET ") != "inet" {
		t.Fatalf("expected normalized family")
	}
	if normalizeFirewallTable(" filter ") != "filter" {
		t.Fatalf("expected normalized table")
	}

	if _, err := normalizeCTStates([]string{"bogus"}); err == nil {
		t.Fatalf("expected invalid ct state error")
	}
	states, err := normalizeCTStates([]string{"related", "established", "related"})
	if err != nil || strings.Join(states, ",") != "established,related" {
		t.Fatalf("unexpected normalized states: states=%v err=%v", states, err)
	}

	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "icmp", Port: 22, Action: "accept"}); err == nil {
		t.Fatalf("expected icmp port validation error")
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "tcp", Action: "accept"}); err == nil {
		t.Fatalf("expected missing port error")
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "tcp", Port: 70000, Action: "accept"}); err == nil {
		t.Fatalf("expected invalid port error")
	}
	tooMany := make([]int, 65536)
	for i := range tooMany {
		tooMany[i] = i + 1
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "tcp", Ports: tooMany, Action: "accept"}); err == nil {
		t.Fatalf("expected too-many-ports error")
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Action: "accept"}); err == nil {
		t.Fatalf("expected missing matcher error")
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "tcp", Port: 22, Action: "allow"}); err == nil {
		t.Fatalf("expected invalid action error")
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "tcp", Ports: []int{22, 443, 22}, Action: "accept"}); err != nil {
		t.Fatalf("expected valid deterministic tcp rule, got %v", err)
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", Proto: "icmp", Action: "accept"}); err != nil {
		t.Fatalf("expected valid icmp rule, got %v", err)
	}
	if _, err := NormalizeDesiredRule(Rule{Chain: "input", InInterface: "lo", Action: "accept"}); err != nil {
		t.Fatalf("expected valid interface-only rule, got %v", err)
	}

	bad := validDeterministicFirewallSpec()
	bad.Family = ""
	if _, err := NormalizeDesiredSpec(bad); err == nil {
		t.Fatalf("expected missing family error")
	}
	bad = validDeterministicFirewallSpec()
	bad.Family = "foo"
	if _, err := NormalizeDesiredSpec(bad); err == nil {
		t.Fatalf("expected unsupported family error")
	}
	bad = validDeterministicFirewallSpec()
	bad.Table = ""
	if _, err := NormalizeDesiredSpec(bad); err == nil {
		t.Fatalf("expected missing table error")
	}
	bad = validDeterministicFirewallSpec()
	bad.Policies = nil
	if _, err := NormalizeDesiredSpec(bad); err == nil {
		t.Fatalf("expected missing policies error")
	}
	bad = validDeterministicFirewallSpec()
	bad.Policies = []Policy{{Chain: "", Policy: "drop"}}
	if _, err := NormalizeDesiredSpec(bad); err == nil {
		t.Fatalf("expected missing chain error")
	}
	bad = validDeterministicFirewallSpec()
	bad.Rules = []Rule{{Chain: "output", Proto: "tcp", Port: 443, Action: "accept"}}
	if _, err := NormalizeDesiredSpec(bad); err == nil || !strings.Contains(err.Error(), "missing policy") {
		t.Fatalf("expected missing policy for rule chain error, got %v", err)
	}

	ports := DecodeNftPortValues([]byte(`{"set":[22,443,"8443"]}`))
	if len(ports) != 3 {
		t.Fatalf("expected 3 ports, got %#v", ports)
	}
	ports = DecodeNftPortValues([]byte(`22`))
	if len(ports) != 1 || ports[0] != 22 {
		t.Fatalf("expected scalar port parse, got %#v", ports)
	}
	if got := DecodeNftStringValue([]byte(`"10.0.0.0/24"`)); got != "10.0.0.0/24" {
		t.Fatalf("expected string decode, got %q", got)
	}
	if got := DecodeNftStringValue([]byte(`22`)); got != "" {
		t.Fatalf("expected empty string decode for non-string, got %q", got)
	}
	strs := DecodeNftStringValues([]byte(`{"set":["related","established"]}`))
	if len(strs) != 2 || strs[0] != "established" || strs[1] != "related" {
		t.Fatalf("unexpected decoded set: %#v", strs)
	}
	if got := DecodeNftStringValue([]byte(`{"set":["icmp"]}`)); got != "icmp" {
		t.Fatalf("expected single-set scalar decode, got %q", got)
	}
	if len(DecodeNftStringValues([]byte(`invalid`))) != 0 {
		t.Fatalf("expected invalid decode to return empty")
	}
}

func TestNormalizeNftRuleExprPaths(t *testing.T) {
	nftJSON := `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"lo"}},
      {"accept":null}
    ]}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"ct":{"key":"state"}},"op":"==","right":{"set":["established","related"]}}},
      {"accept":null}
    ]}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":"icmp"}},
      {"accept":null}
    ]}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":53}},
      {"drop":null}
    ]}}
  ]
}`
	state, err := NormalizeCurrentState(nftJSON, "inet", "filter")
	if err != nil {
		t.Fatalf("NormalizeCurrentState failed: %v", err)
	}
	if len(state.Rules) != 4 {
		t.Fatalf("expected 4 normalized rules, got %d (%#v)", len(state.Rules), state.Rules)
	}

	invalidChain := nftJSONRule{Chain: "wat"}
	if out := normalizeNftRuleExpr(invalidChain); len(out) != 0 {
		t.Fatalf("expected nil for invalid chain, got %#v", out)
	}
	invalidPortProto := nftJSONRule{Chain: "input", Expr: []json.RawMessage{[]byte(`{"match":{"left":{"payload":{"protocol":"ip","field":"dport"}},"right":53}}`), []byte(`{"accept":null}`)}}
	if out := normalizeNftRuleExpr(invalidPortProto); len(out) != 0 {
		t.Fatalf("expected nil for invalid port/proto expression, got %#v", out)
	}
}

func TestNormalizeCurrentStateAcceptsRuntimeNftAliases(t *testing.T) {
	nftJSON := `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
    {"chain":{"family":"inet","table":"filter","name":"forward","type":"filter","hook":"forward","policy":"accept"}},
    {"chain":{"family":"inet","table":"filter","name":"output","type":"filter","hook":"output","policy":"accept"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"op":"==","right":"ipv6-icmp"}},
      {"accept":null}
    ]}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"meta":{"key":"iif"}},"op":"==","right":"lo"}},
      {"accept":null}
    ]}}
  ]
}`

	state, err := NormalizeCurrentState(nftJSON, "inet", "filter")
	if err != nil {
		t.Fatalf("NormalizeCurrentState failed: %v", err)
	}
	if len(state.Rules) != 2 {
		t.Fatalf("expected 2 normalized rules, got %d (%#v)", len(state.Rules), state.Rules)
	}

	want := map[string]struct{}{
		NormalizedRule{Chain: "input", Proto: "icmpv6", Action: "accept"}.key():   {},
		NormalizedRule{Chain: "input", InInterface: "lo", Action: "accept"}.key(): {},
	}
	for _, rule := range state.Rules {
		if _, ok := want[rule.key()]; !ok {
			t.Fatalf("unexpected normalized rule: %#v", rule)
		}
	}
}

func TestFirewallContentDiffHelpers(t *testing.T) {
	if got := firewallCurrentSuffix(true); got != "" {
		t.Fatalf("expected empty suffix for existing file, got %q", got)
	}
	if got := firewallCurrentSuffix(false); got != " (absent)" {
		t.Fatalf("unexpected absent suffix: %q", got)
	}
	edits := diffFirewallLines("line1\nline2\n", "line1\nline3\n")
	if len(edits) == 0 {
		t.Fatalf("expected diff edits")
	}

	diff := renderFirewallContentDiff("/etc/nftables.d/99-hardline-firewall.nft", "line1\nline2\n", "line1\nline3\n", true)
	if len(diff) == 0 {
		t.Fatalf("expected rendered content diff")
	}
	joined := strings.Join(diff, "\n")
	for _, want := range []string{
		`--- current /etc/nftables.d/99-hardline-firewall.nft`,
		`+++ desired /etc/nftables.d/99-hardline-firewall.nft`,
		`-line2`,
		`+line3`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected content diff %q, got %s", want, joined)
		}
	}

	if out := renderFirewallContentDiff("/etc/example.nft", "same\n", "same\n", false); out != nil {
		t.Fatalf("expected nil diff for identical content, got %#v", out)
	}
	if got := splitFirewallDiffLines("a\r\nb\r\n"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("unexpected split lines: %#v", got)
	}

	oversized := strings.Repeat("x\n", firewallDiffMaxLines+1)
	bigEdits := diffFirewallLines(oversized, "y\n")
	if len(bigEdits) != 1 || bigEdits[0].kind != '!' {
		t.Fatalf("expected single notice edit for oversized input, got %#v", bigEdits)
	}
	if !strings.Contains(bigEdits[0].line, "too large") {
		t.Fatalf("expected oversize notice, got %q", bigEdits[0].line)
	}
}

func TestApplyPlanValidateCaptureAndDestination(t *testing.T) {
	t.Run("managed destination", func(t *testing.T) {
		if got := ManagedDestination(nil); got != "" {
			t.Fatalf("unexpected nil destination: %q", got)
		}
		if got := ManagedDestination(&Spec{ManagedDest: " /etc/nftables.d/99-hardline-managed.nft "}); got != "/etc/nftables.d/99-hardline-managed.nft" {
			t.Fatalf("unexpected managed destination: %q", got)
		}
	})

	t.Run("ensure include direct", func(t *testing.T) {
		calls := 0
		err := EnsureNftablesInclude(firewallExecHostStub{runRoot: func(cmd string) error {
			if cmd == testIncludeCheck {
				calls++
				if calls == 1 {
					return errors.New("missing")
				}
			}
			return nil
		}}, testMainConfig, testDest)
		if err != nil {
			t.Fatalf("EnsureNftablesInclude failed: %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected 2 include checks, got %d", calls)
		}

		err = EnsureNftablesInclude(firewallExecHostStub{runRoot: func(cmd string) error {
			if cmd == testIncludeCheck {
				return errors.New("missing")
			}
			if strings.Contains(cmd, ">> '/etc/nftables.conf'") {
				return errors.New("append fail")
			}
			return nil
		}}, testMainConfig, testDest)
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure error, got %v", err)
		}

		calledAppend := false
		err = EnsureNftablesInclude(firewallExecHostStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, ">> '/etc/nftables.conf'") {
				calledAppend = true
			}
			return nil
		}}, testMainConfig, testDest)
		if err != nil {
			t.Fatalf("EnsureNftablesInclude present-include path failed: %v", err)
		}
		if calledAppend {
			t.Fatalf("append should not run when include already present")
		}
	})

	t.Run("apply paths", func(t *testing.T) {
		err := Apply(pluginapi.Context{}, &Spec{Backend: "ufw"})
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected unsupported backend error, got %v", err)
		}

		err = Apply(pluginapi.Context{}, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "host context is required") {
			t.Fatalf("expected host context error, got %v", err)
		}

		spec := validDeterministicFirewallSpec()
		spec.ManagedDest = ""
		err = Apply(pluginapi.Context{Host: firewallExecHostStub{}}, spec)
		if err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
			t.Fatalf("expected managed dest error, got %v", err)
		}

		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(string) error { return errors.New("mkdir fail") },
		}}, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "mkdir -p") {
			t.Fatalf("expected mkdir error, got %v", err)
		}

		checkCount := 0
		cmds := []string{}
		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(cmd string) error {
				cmds = append(cmds, cmd)
				if cmd == testIncludeCheck {
					checkCount++
					if checkCount == 1 {
						return errors.New("missing")
					}
				}
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				return nil
			},
			writeRootFile: func(string, []byte, os.FileMode) error { return nil },
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		appended := strings.Join(cmds, "\n")
		if !strings.Contains(appended, `printf '%s\n' 'include "/etc/nftables.d/99-hardline-firewall.nft"' >> '/etc/nftables.conf'`) {
			t.Fatalf("expected include append command, got %v", cmds)
		}
		if !strings.Contains(appended, `[ -n "$(tail -c 1 '/etc/nftables.conf')" ]`) {
			t.Fatalf("append must terminate an unterminated last line instead of prepending a blank one, got %v", cmds)
		}
		if strings.Contains(appended, `printf '\n%s\n'`) {
			t.Fatalf("a leading blank line survives rollback and breaks byte-identity, got %v", cmds)
		}

		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(cmd string) error {
				if cmd == testIncludeCheck {
					return errors.New("missing")
				}
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				if strings.Contains(cmd, ">> '/etc/nftables.conf'") {
					return errors.New("append failed")
				}
				return nil
			},
			writeRootFile: func(string, []byte, os.FileMode) error { return nil },
		}}, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure include error, got %v", err)
		}

		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(cmd string) error {
				if strings.HasPrefix(cmd, "test -e ") {
					return errors.New("missing")
				}
				return nil
			},
			writeRootFile: func(string, []byte, os.FileMode) error { return errors.New("write failed") },
		}}, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "write firewall candidate") {
			t.Fatalf("expected candidate write error, got %v", err)
		}

		var gotDest string
		var gotData string
		var gotMode os.FileMode
		want, err := NormalizeDesiredSpec(validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("NormalizeDesiredSpec failed: %v", err)
		}
		wantRender := RenderNormalized(want)
		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return fmt.Sprintf("644 %d", len(wantRender)), nil },
			readRootFile:      func(string) (string, error) { return wantRender, nil },
			writeRootFile: func(string, []byte, os.FileMode) error {
				t.Fatalf("write should be skipped when managed firewall file already matches")
				return nil
			},
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		var gotCmds []string
		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(cmd string) error {
				gotCmds = append(gotCmds, cmd)
				return nil
			},
			runRootWithOutput: func(string) (string, error) { return fmt.Sprintf("644 %d", len(wantRender)), nil },
			readRootFile:      func(string) (string, error) { return wantRender + "\n# drift", nil },
			writeRootFile: func(dest string, data []byte, mode os.FileMode) error {
				gotDest, gotData, gotMode = dest, string(data), mode
				return nil
			},
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		candidate := validDeterministicFirewallSpec().ManagedDest + candidateSuffix
		if gotDest != candidate || gotData != wantRender || gotMode != 0o644 {
			t.Fatalf("unexpected write payload: dest=%q mode=%#o", gotDest, gotMode)
		}
		joined := strings.Join(gotCmds, "\n")
		if !strings.Contains(joined, "mv -f '"+candidate+"' '"+validDeterministicFirewallSpec().ManagedDest+"'") {
			t.Fatalf("expected the candidate to be moved into place, got %v", gotCmds)
		}
	})

	t.Run("plan validate capture", func(t *testing.T) {
		res, err := Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "ufw"})
		if err != nil || !strings.Contains(res.Summary, "unsupported backend") {
			t.Fatalf("expected unsupported backend summary, got res=%+v err=%v", res, err)
		}

		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables"})
		if err == nil || !strings.Contains(err.Error(), "family is required") {
			t.Fatalf("expected family required error, got %v", err)
		}
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, Family: "inet"})
		if err == nil || !strings.Contains(err.Error(), "table is required") {
			t.Fatalf("expected table required error, got %v", err)
		}
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, Family: "inet", Table: "filter"})
		if err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
			t.Fatalf("expected managed_dest required error, got %v", err)
		}
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", MainConfig: MainConfigDebian, Family: "inet", Table: "filter", ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft"})
		if err == nil || !strings.Contains(err.Error(), "policies are required") {
			t.Fatalf("expected policies required error, got %v", err)
		}

		res, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{statInfo: fakeFileInfo{mode: 0o644, size: 12}, include: true}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Plan failed: %v", err)
		}
		if len(res.Details) == 0 || !strings.Contains(res.Summary, "deterministic") {
			t.Fatalf("unexpected plan output: %+v", res)
		}
		if len(res.Diff) == 0 {
			t.Fatalf("expected runtime diff for firewall plan, got %+v", res)
		}

		want, err := NormalizeDesiredSpec(validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("NormalizeDesiredSpec failed: %v", err)
		}
		wantRendered := RenderNormalized(want)
		matchingJSON := `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}},
      {"accept":null}
    ]}}
  ]
}`
		res, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{
			statInfo:    fakeFileInfo{mode: 0o644, size: int64(len(wantRendered))},
			include:     true,
			rulesetJSON: matchingJSON,
			readContent: wantRendered,
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Plan matched-state failed: %v", err)
		}
		if res.WillChange {
			t.Fatalf("expected WillChange=false for matched firewall plan, got %+v", res)
		}
		if len(res.Diff) != 0 {
			t.Fatalf("expected no diff for matched firewall plan, got %+v", res.Diff)
		}

		res, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{
			statInfo:    fakeFileInfo{mode: 0o644, size: int64(len(wantRendered) + 8)},
			include:     true,
			rulesetJSON: matchingJSON,
			readContent: wantRendered + "\n# drift",
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Plan drifted-file failed: %v", err)
		}
		if !res.WillChange {
			t.Fatalf("expected WillChange=true for drifted firewall file, got %+v", res)
		}
		joinedDiff := strings.Join(res.Diff, "\n")
		if !strings.Contains(joinedDiff, `--- current /etc/nftables.d/99-hardline-firewall.nft`) || !strings.Contains(joinedDiff, `-# drift`) {
			t.Fatalf("expected managed file diff, got %s", joinedDiff)
		}

		nftJSON := `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"accept"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":53}},
      {"accept":null}
    ]}}
  ]
}`
		res, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{
			statInfo:    fakeFileInfo{mode: 0o644, size: 12},
			include:     true,
			rulesetJSON: nftJSON,
		}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Plan runtime diff failed: %v", err)
		}
		joinedDiff = strings.Join(res.Diff, "\n")
		for _, want := range []string{
			"chain input policy: accept -> drop",
			"- tcp dport 53 accept",
			"+ tcp dport 22 accept",
		} {
			if !strings.Contains(joinedDiff, want) {
				t.Fatalf("expected runtime diff %q, got %s", want, joinedDiff)
			}
		}

		if err := ValidateApply(firewallExecHostStub{runRoot: func(string) error { return nil }}, testMainConfig, testDest); err != nil {
			t.Fatalf("ValidateApply failed: %v", err)
		}
		err = ValidateApply(firewallExecHostStub{runRoot: func(cmd string) error {
			if cmd == testIncludeCheck {
				return errors.New("missing")
			}
			return nil
		}}, testMainConfig, testDest)
		if err == nil || !strings.Contains(err.Error(), "missing include") {
			t.Fatalf("expected include error, got %v", err)
		}
		err = ValidateApply(firewallExecHostStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "nft -c") {
				return errors.New("bad")
			}
			return nil
		}}, testMainConfig, testDest)
		if err == nil || !strings.Contains(err.Error(), "config check failed") {
			t.Fatalf("expected config check error, got %v", err)
		}

		res, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{include: false}}, validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Plan with missing include failed: %v", err)
		}
		if len(res.Highlights) != 0 {
			t.Fatalf("missing include should not produce highlights (NEEDS ATTENTION), got %v", res.Highlights)
		}
		includeDiff := strings.Join(res.Diff, "\n")
		if !strings.Contains(includeDiff, "add include") {
			t.Fatalf("expected 'add include' in diff for missing include, got %s", includeDiff)
		}

		vres, err := ValidatePlan(firewallRuntimeStub{include: false, configErr: errors.New("bad")}, testMainConfig, testDest)
		if err != nil {
			t.Fatalf("ValidatePlan failed: %v", err)
		}
		joined := strings.Join(vres.Details, "\n")
		if !strings.Contains(joined, "missing") || !strings.Contains(joined, "reports errors") {
			t.Fatalf("unexpected validate plan details: %s", joined)
		}
		vres, err = ValidatePlan(firewallRuntimeStub{include: true}, testMainConfig, testDest)
		if err != nil {
			t.Fatalf("ValidatePlan success path failed: %v", err)
		}
		if !strings.Contains(strings.Join(vres.Details, "\n"), "is present") {
			t.Fatalf("expected include-present detail, got %+v", vres.Details)
		}

		_, err = Capture(pluginapi.Context{}, "f", nil)
		if err == nil || !strings.Contains(err.Error(), "firewall spec missing") {
			t.Fatalf("expected missing spec error, got %v", err)
		}
		_, err = Capture(pluginapi.Context{Host: firewallExecHostStub{}}, "f", &Spec{ManagedDest: "/tmp/nope.nft"})
		if err == nil || !strings.Contains(err.Error(), "outside /etc") {
			t.Fatalf("expected managed path error, got %v", err)
		}
		_, err = Capture(pluginapi.Context{Host: firewallExecHostStub{
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "", errors.New("stat bad") },
			readRootFile:      func(string) (string, error) { return "", nil },
		}}, "f", validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "capture firewall snapshot") {
			t.Fatalf("expected snapshot error, got %v", err)
		}
		rec, err := Capture(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(string) error { return nil },
			runRootWithOutput: func(cmd string) (string, error) {
				if strings.Contains(cmd, "nft -j list ruleset") {
					return "", nil
				}
				return "regular file|644|root|root|5", nil
			},
			readRootFile: func(string) (string, error) { return "abc", nil },
		}}, "f", validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 4 {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
		if rec.Objects[3].Kind != pluginapi.ObjectRuntimePolicy || rec.Objects[3].RuntimePolicy == nil {
			t.Fatalf("the loaded ruleset was not journalled: %+v", rec.Objects[3])
		}
		include := rec.Objects[2].ConfigLine
		if rec.Objects[2].Kind != pluginapi.ObjectConfigLine || include == nil || include.Path != MainConfigDebian {
			t.Fatalf("expected the %s include captured last, got %+v", MainConfigDebian, rec.Objects[2])
		}
		flush := rec.Objects[1].ConfigLine
		if rec.Objects[1].Kind != pluginapi.ObjectConfigLine || flush == nil || flush.Line != FlushLine {
			t.Fatalf("expected the flush header captured with the include, got %+v", rec.Objects[1])
		}
		if include.Line != `include "/etc/nftables.d/99-hardline-firewall.nft"` {
			t.Fatalf("expected the exact managed file to be included, got %q", include.Line)
		}
		if rec.Objects[0].File == nil || rec.Objects[0].File.Path != ManagedDestination(validDeterministicFirewallSpec()) {
			t.Fatalf("expected managed destination captured first, got %+v", rec.Objects[0].File)
		}
	})

	t.Run("a load that leaves the files alone is still journalled", func(t *testing.T) {
		spec := validDeterministicFirewallSpec()
		host := func(ruleset string) firewallExecHostStub {
			return firewallExecHostStub{
				runRoot: func(string) error { return nil },
				runRootWithOutput: func(cmd string) (string, error) {
					if strings.Contains(cmd, "nft -j list ruleset") {
						return ruleset, nil
					}
					return "regular file|644|root|root|5", nil
				},
				readRootFile: func(string) (string, error) { return "abc", nil },
			}
		}

		before, err := Capture(pluginapi.Context{Host: host(`{"nftables":[]}`)}, "f", spec)
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		after, err := Capture(pluginapi.Context{Host: host(liveRulesetJSON(normalizedTestSpec(t, spec)))}, "f", spec)
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if !pluginapi.CapturesDiffer(before, after) {
			t.Fatal("a load that changed the kernel ruleset without touching a file was not journalled as a change")
		}
	})

	t.Run("current firewall state empty ruleset", func(t *testing.T) {
		state, err := currentFirewallState(firewallRuntimeStub{}, "inet", "filter")
		if err != nil {
			t.Fatalf("currentFirewallState failed: %v", err)
		}
		if state.Family != "inet" || state.Table != "filter" || len(state.Policies) != 0 || len(state.Rules) != 0 {
			t.Fatalf("unexpected empty state: %#v", state)
		}
	})
}

func TestExtraDecodeAndRenderBranches(t *testing.T) {
	for _, pol := range []string{"accept", "drop", "reject"} {
		if got, err := NormalizePolicy(pol); err != nil || got != pol {
			t.Fatalf("expected policy %q to normalize, got %q err=%v", pol, got, err)
		}
	}

	if out := DecodeNftPortValues([]byte(`[53,"54"]`)); len(out) != 2 || out[0] != 53 || out[1] != 54 {
		t.Fatalf("expected array port decode, got %#v", out)
	}
	if out := DecodeNftPortValues([]byte(`{"set":"bad"}`)); len(out) != 0 {
		t.Fatalf("expected empty decode for bad set payload, got %#v", out)
	}

	if out := DecodeNftStringValues([]byte(`["A","b"]`)); strings.Join(out, ",") != "a,b" {
		t.Fatalf("expected normalized string list, got %#v", out)
	}
	if got := DecodeNftStringValue([]byte(`{"set":["a","b"]}`)); got != "" {
		t.Fatalf("expected empty scalar for multi-set, got %q", got)
	}

	icmpv6Line := RenderNormalizedRule("ip6", NormalizedRule{Proto: "icmpv6", Action: "reject"})
	if !strings.Contains(icmpv6Line, "ip6 nexthdr icmpv6") || !strings.Contains(icmpv6Line, "reject") {
		t.Fatalf("unexpected icmpv6 rule render: %q", icmpv6Line)
	}

	nftJSON := `{
  "nftables": [
    {"rule":{"family":"ip6","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"op":"==","right":"icmpv6"}},
      {"reject":null}
    ]}}
  ]
}`
	out, err := NormalizeCurrentState(nftJSON, "ip6", "filter")
	if err != nil {
		t.Fatalf("NormalizeCurrentState ip6 failed: %v", err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Proto != "icmpv6" || out.Rules[0].Action != "reject" {
		t.Fatalf("unexpected ip6 normalized rules: %#v", out.Rules)
	}

	aliasJSON := `{
  "nftables": [
    {"rule":{"family":"ip6","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"op":"==","right":"ipv6-icmp"}},
      {"reject":null}
    ]}}
  ]
}`
	out, err = NormalizeCurrentState(aliasJSON, "ip6", "filter")
	if err != nil {
		t.Fatalf("NormalizeCurrentState ip6 alias failed: %v", err)
	}
	if len(out.Rules) != 1 || out.Rules[0].Proto != "icmpv6" || out.Rules[0].Action != "reject" {
		t.Fatalf("unexpected ip6 alias normalized rules: %#v", out.Rules)
	}
}

func TestDestinationHelpersAndPlugin(t *testing.T) {
	t.Run("stat destination helper", func(t *testing.T) {
		if _, _, err := statFirewallDestination(nil, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "runtime is required") {
			t.Fatalf("expected runtime error, got %v", err)
		}

		size, mode, err := statFirewallDestination(firewallHelperRuntimeStub{runRootErr: errors.New("missing")}, "/etc/example.conf")
		if err != nil || size != -1 || mode != 0 {
			t.Fatalf("unexpected missing result size=%d mode=%#o err=%v", size, mode, err)
		}

		if _, _, err := statFirewallDestination(firewallHelperRuntimeStub{runRootWithOutputErr: errors.New("boom")}, "/etc/example.conf"); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("expected stat command error, got %v", err)
		}

		for _, raw := range []string{"bad", "xyz 5", "644 bad", "644 5 extra"} {
			if _, _, err := statFirewallDestination(firewallHelperRuntimeStub{runRootWithOutput: raw}, "/etc/example.conf"); err == nil {
				t.Fatalf("expected parse error for %q", raw)
			}
		}

		size, mode, err = statFirewallDestination(firewallHelperRuntimeStub{runRootWithOutput: "644 12"}, "/etc/example.conf")
		if err != nil || size != 12 || mode.Perm() != 0o644 {
			t.Fatalf("unexpected success result size=%d mode=%#o err=%v", size, mode, err)
		}
	})

	t.Run("destination matches helper", func(t *testing.T) {
		matches, err := firewallDestinationMatches(
			firewallHelperRuntimeStub{runRootWithOutput: "644 12", readContent: "hello world!"},
			"/etc/example.conf",
			"hello world!",
			0o644,
		)
		if err != nil || !matches {
			t.Fatalf("expected matching destination, got matches=%v err=%v", matches, err)
		}

		matches, err = firewallDestinationMatches(
			firewallHelperRuntimeStub{runRootWithOutput: "600 12", readContent: "hello world!"},
			"/etc/example.conf",
			"hello world!",
			0o644,
		)
		if err != nil || matches {
			t.Fatalf("expected mode mismatch to skip compare result, got matches=%v err=%v", matches, err)
		}

		matches, err = firewallDestinationMatches(
			firewallHelperRuntimeStub{runRootWithOutput: "644 12", readErr: errors.New("boom")},
			"/etc/example.conf",
			"hello world!",
			0o644,
		)
		if err == nil || !strings.Contains(err.Error(), "boom") || matches {
			t.Fatalf("expected read error, got matches=%v err=%v", matches, err)
		}
	})

	t.Run("validate helper utilities", func(t *testing.T) {
		if firewallIncludePresent(nil, testMainConfig, testDest) {
			t.Fatalf("nil runtime should report missing include")
		}
		if !firewallIncludePresent(firewallRuntimeStub{include: true}, testMainConfig, testDest) {
			t.Fatalf("expected include to be detected")
		}
		if err := firewallConfigTest(nil, testMainConfig); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected runtime-required error, got %v", err)
		}
		if err := firewallConfigTest(firewallRuntimeStub{configErr: errors.New("bad")}, testMainConfig); err == nil || !strings.Contains(err.Error(), "bad") {
			t.Fatalf("expected nft config error, got %v", err)
		}
	})

	t.Run("plugin decode errors", func(t *testing.T) {
		plugin := Plugin()
		step := profile.Step{
			ID:     "bad-firewall",
			Plugin: "firewall",
			Config: map[string]any{"backend": 1},
		}

		if err := plugin.Apply(pluginapi.Context{}, step); err == nil {
			t.Fatalf("expected plugin apply decode error")
		}
		if _, err := plugin.Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, step); err == nil {
			t.Fatalf("expected plugin plan decode error")
		}
		if _, err := plugin.Capture(pluginapi.Context{}, step); err == nil {
			t.Fatalf("expected plugin rollback decode error")
		}
	})
}

func validDeterministicFirewallSpec() *Spec {
	return &Spec{
		Backend:     "nftables",
		MainConfig:  testMainConfig,
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []Policy{
			{Chain: "input", Policy: "drop"},
		},
		Rules: []Rule{
			{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
		},
	}
}

func activationProbeAnswer(cmd string, noSSHD bool, liveJSON string) (string, bool) {
	switch {
	case strings.HasPrefix(cmd, "if test -f "):
		return "HL:present", true
	case strings.HasPrefix(cmd, "ss -Hltnp"):
		if noSSHD {
			return "", true
		}
		return `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))`, true
	case strings.Contains(cmd, "nft -j list ruleset"):
		if liveJSON != "" {
			return liveJSON, true
		}
		return standardLiveRulesetJSON, true
	}
	return "", false
}

var standardLiveRulesetJSON = mustLiveRulesetJSON(validDeterministicFirewallSpec())

func mustLiveRulesetJSON(spec *Spec) string {
	normalized, err := NormalizeDesiredSpec(spec)
	if err != nil {
		panic("build live ruleset fixture: " + err.Error())
	}
	return liveRulesetJSON(normalized)
}

func liveRulesetJSON(spec NormalizedSpec) string {
	entries := []string{fmt.Sprintf(`{"table":{"family":%q,"name":%q}}`, spec.Family, spec.Table)}

	chains := make([]string, 0, len(spec.Policies))
	for chain := range spec.Policies {
		chains = append(chains, chain)
	}
	sort.Strings(chains)
	for _, chain := range chains {
		entries = append(entries, fmt.Sprintf(
			`{"chain":{"family":%q,"table":%q,"name":%q,"type":"filter","hook":%q,"policy":%q}}`,
			spec.Family, spec.Table, chain, chain, spec.Policies[chain]))
	}

	for _, rule := range spec.Rules {
		var exprs []string
		if rule.InInterface != "" {
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":%q}}`, rule.InInterface))
		}
		if rule.OutInterface != "" {
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":%q}}`, rule.OutInterface))
		}
		if rule.Source != "" {
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"payload":{"protocol":%q,"field":"saddr"}},"op":"==","right":%q}}`,
				addressKeyword(spec.Family, rule.Source), rule.Source))
		}
		if rule.Destination != "" {
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"payload":{"protocol":%q,"field":"daddr"}},"op":"==","right":%q}}`,
				addressKeyword(spec.Family, rule.Destination), rule.Destination))
		}
		if len(rule.CTStates) > 0 {
			quoted := make([]string, 0, len(rule.CTStates))
			for _, state := range rule.CTStates {
				quoted = append(quoted, fmt.Sprintf("%q", state))
			}
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"ct":{"key":"state"}},"op":"in","right":[%s]}}`, strings.Join(quoted, ",")))
		}
		switch rule.Proto {
		case "tcp", "udp":
			exprs = append(exprs, fmt.Sprintf(`{"match":{"left":{"payload":{"protocol":%q,"field":"dport"}},"op":"==","right":%d}}`, rule.Proto, rule.Port))
		case "icmp":
			exprs = append(exprs, `{"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":"icmp"}}`)
		case "icmpv6":
			exprs = append(exprs, `{"match":{"left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"op":"==","right":"icmpv6"}}`)
		}
		exprs = append(exprs, fmt.Sprintf(`{%q:null}`, rule.Action))

		entries = append(entries, fmt.Sprintf(`{"rule":{"family":%q,"table":%q,"chain":%q,"expr":[%s]}}`,
			spec.Family, spec.Table, rule.Chain, strings.Join(exprs, ",")))
	}

	return `{"nftables":[` + strings.Join(entries, ",") + `]}`
}

type fakeFileInfo struct {
	mode os.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return "x" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

type firewallRuntimeStub struct {
	statInfo    os.FileInfo
	include     bool
	legacyGlob  bool
	configErr   error
	rulesetJSON string
	rulesetErr  error
	readContent string
	readErr     error
}

func (s firewallRuntimeStub) RunRoot(cmd string) error {
	switch cmd {
	case testLegacyGlobCheck:
		if s.legacyGlob {
			return nil
		}
		return errors.New("no legacy glob")
	case testIncludeCheck:
		if s.include {
			return nil
		}
		return errors.New("missing")
	case "nft -c -f '" + MainConfigDebian + "' >/dev/null 2>&1",
		"nft -c -f '" + MainConfigRHEL + "' >/dev/null 2>&1":
		return s.configErr
	default:
		return nil
	}
}

func (s firewallRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if strings.Contains(cmd, "nft -j list ruleset") {
		return s.rulesetJSON, s.rulesetErr
	}
	return "", nil
}

func (s firewallRuntimeStub) Stat(string) (os.FileInfo, error) {
	if s.statInfo == nil {
		return nil, errors.New("missing")
	}
	return s.statInfo, nil
}
func (s firewallRuntimeStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}

func (firewallRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func (s firewallRuntimeStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

type firewallHelperRuntimeStub struct {
	legacyGlob           bool
	noSSHD               bool
	liveRulesetJSON      string
	runRootErr           error
	runRootWithOutput    string
	runRootWithOutputErr error
	readContent          string
	readErr              error
}

func (s firewallHelperRuntimeStub) RunRoot(cmd string) error {
	if cmd == testLegacyGlobCheck && !s.legacyGlob {
		return errors.New("no legacy glob")
	}
	return s.runRootErr
}

func (s firewallHelperRuntimeStub) RunRootWithOutput(cmd string) (string, error) {
	if answer, ok := activationProbeAnswer(cmd, s.noSSHD, s.liveRulesetJSON); ok {
		return answer, nil
	}
	if s.runRootWithOutputErr != nil {
		return "", s.runRootWithOutputErr
	}
	if strings.Contains(cmd, "%F|") {
		fields := strings.Fields(s.runRootWithOutput)
		if len(fields) != 2 {
			return s.runRootWithOutput, nil
		}
		return "regular file|" + fields[0] + "|root|root|" + fields[1], nil
	}
	return s.runRootWithOutput, s.runRootWithOutputErr
}

func (firewallHelperRuntimeStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("missing") }

func (s firewallHelperRuntimeStub) ReadRootFile(string) (string, error) {
	if s.readErr != nil {
		return "", s.readErr
	}
	return s.readContent, nil
}

func (firewallHelperRuntimeStub) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func (s firewallHelperRuntimeStub) RunRootWithTimeout(string, time.Duration) (string, error) {
	return s.runRootWithOutput, s.runRootWithOutputErr
}

type firewallExecHostStub struct {
	legacyGlob        bool
	noSSHD            bool
	liveRulesetJSON   string
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s firewallExecHostStub) RunRoot(cmd string) error {
	if cmd == testLegacyGlobCheck && !s.legacyGlob {
		return errors.New("no legacy glob")
	}
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s firewallExecHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput != nil {
		out, err := s.runRootWithOutput(cmd)
		if err != nil || strings.TrimSpace(out) != "" {
			return out, err
		}
	}
	if answer, ok := activationProbeAnswer(cmd, s.noSSHD, s.liveRulesetJSON); ok {
		return answer, nil
	}
	return "", nil
}

func (firewallExecHostStub) Stat(string) (os.FileInfo, error) { return nil, errors.New("missing") }

func (s firewallExecHostStub) ReadRootFile(path string) (string, error) {
	if s.readRootFile == nil {
		return "", nil
	}
	return s.readRootFile(path)
}

func (s firewallExecHostStub) WriteRootFile(path string, data []byte, mode os.FileMode) error {
	if s.writeRootFile == nil {
		return nil
	}
	return s.writeRootFile(path, data, mode)
}

func (s firewallExecHostStub) RunRootWithTimeout(cmd string, _ time.Duration) (string, error) {
	return s.RunRootWithOutput(cmd)
}

func TestRollbackRemovesOnlyItsOwnInclude(t *testing.T) {
	const other = `include "/etc/nftables.d/50-other.nft"`
	current := "flush ruleset\n\n" + IncludeLine(testDest) + "\n" + other + "\n"

	var wrote string
	var wroteMode os.FileMode
	host := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
		writeRootFile: func(_ string, data []byte, mode os.FileMode) error {
			wrote = string(data)
			wroteMode = mode
			return nil
		},
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        testMainConfig,
		Line:        IncludeLine(testDest),
		FileExisted: true,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if strings.Contains(wrote, testDest) {
		t.Fatalf("expected our include to be gone, got %q", wrote)
	}
	if !strings.Contains(wrote, other) {
		t.Fatalf("expected the other profile's include to survive, got %q", wrote)
	}
	if !strings.Contains(wrote, "flush ruleset") {
		t.Fatalf("expected the rest of the file to survive, got %q", wrote)
	}
	if wroteMode.Perm() != 0o644 {
		t.Fatalf("expected the file's own mode to be preserved, got %v", wroteMode)
	}
}

func TestRollbackLeavesAnIncludeItDidNotAdd(t *testing.T) {
	host := firewallExecHostStub{writeRootFile: func(string, []byte, os.FileMode) error {
		t.Fatal("a line this run did not add must not be rewritten")
		return nil
	}}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        testMainConfig,
		Line:        IncludeLine(testDest),
		FileExisted: true,
		Added:       false,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
}

func TestRollbackRemovesAMainConfigItCreated(t *testing.T) {
	current := FlushMarker + "\n" + FlushLine + "\n" + IncludeLine(testDest) + "\n"
	var cmds []string
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        testMainConfig,
		Line:        IncludeLine(testDest),
		FileExisted: false,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "rm -f '"+testMainConfig+"'") {
		t.Fatalf("expected the created main config to be removed, got %v", cmds)
	}
}

func TestRollbackKeepsAMainConfigCarryingContentHardlineNeverWrote(t *testing.T) {
	for name, extra := range map[string]string{
		"an unmanaged include": `include "/etc/nftables.d/50-other.nft"`,
		"an inline ruleset":    "table inet ops { chain input { type filter hook input priority 0; } }",
	} {
		t.Run(name, func(t *testing.T) {
			current := FlushMarker + "\n" + FlushLine + "\n" + IncludeLine(testDest) + "\n" + extra + "\n"
			var cmds []string
			host := firewallExecHostStub{
				runRoot: func(cmd string) error {
					cmds = append(cmds, cmd)
					return nil
				},
				runRootWithOutput: func(string) (string, error) {
					return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
				},
				readRootFile:  func(string) (string, error) { return current, nil },
				writeRootFile: func(string, []byte, os.FileMode) error { return nil },
			}

			err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
				Path:        testMainConfig,
				Line:        IncludeLine(testDest),
				FileExisted: false,
				Added:       true,
			})
			if err != nil {
				t.Fatalf("RestoreNftablesInclude failed: %v", err)
			}
			if strings.Contains(strings.Join(cmds, "\n"), "rm -f '"+testMainConfig+"'") {
				t.Fatalf("a main config carrying %s must survive, got %v", name, cmds)
			}
		})
	}
}

func TestRestoreNftablesIncludeRejectsAForeignPath(t *testing.T) {
	err := RestoreNftablesInclude(firewallExecHostStub{}, pluginapi.ConfigLineSnapshot{
		Path:        "/etc/passwd",
		Line:        IncludeLine(testDest),
		FileExisted: true,
		Added:       true,
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected main config path") {
		t.Fatalf("expected a rejected path, got %v", err)
	}
}

func TestApplyRefusesTheLegacyGlobInclude(t *testing.T) {
	host := firewallExecHostStub{legacyGlob: true}
	err := EnsureNftablesInclude(host, testMainConfig, testDest)
	if err == nil || !strings.Contains(err.Error(), "directory-wide include") {
		t.Fatalf("expected the legacy glob to be refused, got %v", err)
	}
}

func TestDiffReportsReorderedChain(t *testing.T) {
	desired, err := NormalizeDesiredSpec(&Spec{
		Backend:     "nftables",
		MainConfig:  testMainConfig,
		ManagedDest: testDest,
		Family:      "inet",
		Table:       "filter",
		Policies:    []Policy{{Chain: "input", Policy: "drop"}},
		Rules: []Rule{
			{Chain: "input", Proto: "tcp", Port: 22, Action: "drop", Source: "10.0.0.1"},
			{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
		},
	})
	if err != nil {
		t.Fatalf("NormalizeDesiredSpec failed: %v", err)
	}
	if desired.Rules[0].Action != "drop" {
		t.Fatalf("declared order must survive normalization, got %+v", desired.Rules)
	}

	swapped := NormalizedSpec{
		Family:   desired.Family,
		Table:    desired.Table,
		Policies: desired.Policies,
		Rules:    []NormalizedRule{desired.Rules[1], desired.Rules[0]},
	}

	diff := DiffNormalized(swapped, desired)
	if len(diff.RulesToAdd) != 0 || len(diff.RulesToRemove) != 0 {
		t.Fatalf("expected no membership change, got %+v", diff)
	}
	if len(diff.Reordered) != 1 || diff.Reordered[0] != "input" {
		t.Fatalf("expected the input chain reported as reordered, got %v", diff.Reordered)
	}

	if aligned := DiffNormalized(desired, desired); len(aligned.Reordered) != 0 {
		t.Fatalf("expected no reorder against itself, got %v", aligned.Reordered)
	}
}

func TestIncludeLineConflictReportsARemovedInclude(t *testing.T) {
	rec := pluginapi.ConfigLineSnapshot{
		Path:        testMainConfig,
		Line:        IncludeLine(testDest),
		FileExisted: true,
		Added:       false,
	}

	present := firewallExecHostStub{runRoot: func(cmd string) error {
		if cmd == testIncludeCheck {
			return nil
		}
		return nil
	}}
	if got := includeLineConflict(present, rec); got != nil {
		t.Fatalf("expected no conflict while the include is present, got %v", got)
	}

	gone := firewallExecHostStub{runRoot: func(cmd string) error {
		if cmd == testIncludeCheck {
			return errors.New("missing")
		}
		return nil
	}}
	conflicts := includeLineConflict(gone, rec)
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], "no longer contains") {
		t.Fatalf("expected a removed-include conflict, got %v", conflicts)
	}

	rec.Added = true
	if got := includeLineConflict(gone, rec); got != nil {
		t.Fatalf("an after snapshot taken while the line was still absent claims nothing, got %v", got)
	}
	rec.Added = false
	if got := includeLineConflict(nil, rec); got != nil {
		t.Fatalf("expected no conflict without a host, got %v", got)
	}
}

func TestRemoveNftablesIncludeEdgeCases(t *testing.T) {
	if err := RemoveNftablesInclude(nil, testMainConfig, IncludeLine(testDest)); err == nil {
		t.Fatal("expected a host to be required")
	}
	if err := RemoveNftablesInclude(firewallExecHostStub{}, "/etc/evil.conf", IncludeLine(testDest)); err == nil {
		t.Fatal("expected a foreign main config to be refused")
	}

	absent := firewallExecHostStub{runRootWithOutput: func(string) (string, error) {
		return "", nil
	}}
	if err := RemoveNftablesInclude(absent, testMainConfig, IncludeLine(testDest)); err != nil {
		t.Fatalf("expected an absent main config to be a no-op, got %v", err)
	}

	const content = "flush ruleset\n"
	untouched := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(content)), nil
		},
		readRootFile: func(string) (string, error) { return content, nil },
		writeRootFile: func(string, []byte, os.FileMode) error {
			t.Fatal("a file without our include must not be rewritten")
			return nil
		},
	}
	if err := RemoveNftablesInclude(untouched, testMainConfig, IncludeLine(testDest)); err != nil {
		t.Fatalf("expected a no-op, got %v", err)
	}

	if _, removed := withoutIncludeLine("flush ruleset\n", "not an include line"); removed {
		t.Fatal("a malformed line must not match anything")
	}
}

func TestNormalizeRejectsUnparsedFields(t *testing.T) {
	base := func() *Spec {
		return &Spec{
			Backend:     "nftables",
			MainConfig:  testMainConfig,
			ManagedDest: testDest,
			Family:      "inet",
			Table:       "filter",
			Policies:    []Policy{{Chain: "input", Policy: "drop"}},
			Rules:       []Rule{{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"}},
		}
	}

	cases := []struct {
		name string
		with func(*Spec)
		want string
	}{
		{
			name: "table carrying more grammar",
			with: func(s *Spec) { s.Table = `filter { }; include "/tmp/evil.nft` },
			want: "not an nftables identifier",
		},
		{
			name: "table with a space",
			with: func(s *Spec) { s.Table = "my filter" },
			want: "not an nftables identifier",
		},
		{
			name: "interface closing its own quote",
			with: func(s *Spec) { s.Rules[0].InInterface = `lo" accept; iif "eth0` },
			want: "is not an interface name",
		},
		{
			name: "interface longer than the kernel allows",
			with: func(s *Spec) { s.Rules[0].InInterface = "abcdefghijklmnop" },
			want: "is not an interface name",
		},
		{
			name: "source that is a second statement",
			with: func(s *Spec) { s.Rules[0].Source = "10.0.0.1; drop" },
			want: "is not an address or CIDR prefix",
		},
		{
			name: "source as an nft range",
			with: func(s *Spec) { s.Rules[0].Source = "10.0.0.1-10.0.0.9" },
			want: "is not an address or CIDR prefix",
		},
		{
			name: "source as a named set",
			with: func(s *Spec) { s.Rules[0].Source = "@trusted" },
			want: "is not an address or CIDR prefix",
		},
		{
			name: "destination hostname",
			with: func(s *Spec) { s.Rules[0].Destination = "example.com" },
			want: "is not an address or CIDR prefix",
		},
		{
			name: "prefix with host bits set",
			with: func(s *Spec) { s.Rules[0].Source = "10.0.0.5/24" },
			want: "has host bits set",
		},
		{
			name: "reject as a base-chain policy",
			with: func(s *Spec) { s.Policies[0].Policy = "reject" },
			want: "not a valid base-chain policy",
		},
		{
			name: "IPv6 address in an ip table",
			with: func(s *Spec) { s.Family = "ip"; s.Rules[0].Source = "2001:db8::1" },
			want: "which an \"ip\" table cannot match",
		},
		{
			name: "IPv4 address in an ip6 table",
			with: func(s *Spec) { s.Family = "ip6"; s.Rules[0].Source = "10.0.0.1" },
			want: "which an \"ip6\" table cannot match",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := base()
			tc.with(spec)
			_, err := NormalizeDesiredSpec(spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected an error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestNormalizeAcceptsOrdinaryAddressesAndInterfaces(t *testing.T) {
	spec, err := NormalizeDesiredSpec(&Spec{
		Backend:     "nftables",
		MainConfig:  testMainConfig,
		ManagedDest: testDest,
		Family:      "inet",
		Table:       "filter",
		Policies:    []Policy{{Chain: "input", Policy: "drop"}},
		Rules: []Rule{
			{Chain: "input", InInterface: "lo", Action: "accept"},
			{Chain: "input", InInterface: "ens4.100", Proto: "tcp", Port: 22, Source: "10.0.0.0/8", Action: "accept"},
			{Chain: "input", Proto: "tcp", Port: 443, Source: "2001:db8::/32", Action: "accept"},
			{Chain: "input", Proto: "udp", Port: 53, Destination: "192.0.2.10", Action: "accept"},
		},
	})
	if err != nil {
		t.Fatalf("expected an ordinary ruleset to normalize, got %v", err)
	}

	rendered := RenderNormalized(spec)
	for _, want := range []string{
		`iif "lo" accept`,
		`iif "ens4.100" ip saddr 10.0.0.0/8 tcp dport 22 accept`,
		`ip6 saddr 2001:db8::/32 tcp dport 443 accept`,
		`ip daddr 192.0.2.10 udp dport 53 accept`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected %q in the rendered ruleset:\n%s", want, rendered)
		}
	}
}

func TestApplyNeverInstallsACandidateNftRejects(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	candidate := spec.ManagedDest + candidateSuffix

	var cmds []string
	err := Apply(pluginapi.Context{Host: firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			if strings.HasPrefix(cmd, "test -e ") {
				return errors.New("missing")
			}
			return nil
		},
		runRootWithOutput: func(cmd string) (string, error) {
			if strings.HasPrefix(cmd, "nft -c -f ") {
				return "/etc/nftables.d/x.nft:3:1-5: Error: syntax error, unexpected junk\njunk\n^^^^", errors.New("exit status 1")
			}
			return "", nil
		},
		writeRootFile: func(string, []byte, os.FileMode) error { return nil },
	}}, spec)

	if err == nil || !strings.Contains(err.Error(), "rejected by nft") {
		t.Fatalf("expected the candidate to be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("expected nft's own complaint in the error, got %v", err)
	}

	joined := strings.Join(cmds, "\n")
	if strings.Contains(joined, "mv -f ") {
		t.Fatalf("a rejected candidate must not be moved into place, got %v", cmds)
	}
	if !strings.Contains(joined, "rm -f '"+candidate+"'") {
		t.Fatalf("expected the rejected candidate to be cleaned up, got %v", cmds)
	}
	if strings.Contains(joined, ">> '/etc/nftables.conf'") {
		t.Fatalf("a rejected candidate must not be wired into the main config, got %v", cmds)
	}
}

func TestApplyCleansUpAfterAFailedInstall(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	candidate := spec.ManagedDest + candidateSuffix

	var cmds []string
	err := Apply(pluginapi.Context{Host: firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			if strings.HasPrefix(cmd, "test -e ") {
				return errors.New("missing")
			}
			if strings.HasPrefix(cmd, "mv -f ") {
				return errors.New("read-only filesystem")
			}
			return nil
		},
		writeRootFile: func(string, []byte, os.FileMode) error { return nil },
	}}, spec)

	if err == nil || !strings.Contains(err.Error(), "install firewall candidate") {
		t.Fatalf("expected an install error, got %v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "rm -f '"+candidate+"'") {
		t.Fatalf("expected the staged candidate to be cleaned up, got %v", cmds)
	}
}

func TestEnsureNftablesFlushPutsTheHeaderFirst(t *testing.T) {
	const existing = "# managed by the distribution\ninclude \"/etc/nftables.d/50-other.nft\"\n"

	var wrote string
	var wroteMode os.FileMode
	present := false
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			if cmd == flushCheckCmd(MainConfigRHEL) && !present {
				return errors.New("absent")
			}
			return nil
		},
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|600|root|root|%d", len(existing)), nil
		},
		readRootFile: func(string) (string, error) { return existing, nil },
		writeRootFile: func(_ string, data []byte, mode os.FileMode) error {
			wrote, wroteMode = string(data), mode
			present = true
			return nil
		},
	}

	if err := EnsureNftablesFlush(host, MainConfigRHEL); err != nil {
		t.Fatalf("EnsureNftablesFlush failed: %v", err)
	}
	if !strings.HasPrefix(wrote, FlushMarker+"\n"+FlushLine+"\n") {
		t.Fatalf("the flush header must lead the file, under the marker that says hardline wrote it, got %q", wrote)
	}
	if !strings.Contains(wrote, `include "/etc/nftables.d/50-other.nft"`) {
		t.Fatalf("expected the existing content to survive, got %q", wrote)
	}
	if wroteMode.Perm() != 0o600 {
		t.Fatalf("expected the file's own mode to be preserved, got %v", wroteMode)
	}
}

func TestEnsureNftablesFlushIsANoOpWhenPresent(t *testing.T) {
	host := firewallExecHostStub{
		runRoot: func(string) error { return nil },
		writeRootFile: func(string, []byte, os.FileMode) error {
			t.Fatal("a config that already flushes must not be rewritten")
			return nil
		},
	}
	if err := EnsureNftablesFlush(host, MainConfigDebian); err != nil {
		t.Fatalf("EnsureNftablesFlush failed: %v", err)
	}
}

func TestEnsureNftablesFlushGuards(t *testing.T) {
	if err := EnsureNftablesFlush(nil, MainConfigDebian); err == nil {
		t.Fatal("expected a host to be required")
	}
	if err := EnsureNftablesFlush(firewallExecHostStub{}, "/etc/evil.conf"); err == nil {
		t.Fatal("expected a foreign main config to be refused")
	}
}

func TestRollbackReloadsTheKernelRuleset(t *testing.T) {
	snap := pluginapi.FileSnapshot{Path: testDest, Existed: false}

	t.Run("loads the restored main config", func(t *testing.T) {
		var cmds []string
		host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
			cmds = append(cmds, cmd)
			return "", nil
		}}
		if err := RestoreManagedRuleset(host, snap, MainConfigDebian); err != nil {
			t.Fatalf("RestoreManagedRuleset failed: %v", err)
		}
		if !containsCmd(cmds, "nft -f "+pluginapi.ShellArg(MainConfigDebian)) {
			t.Fatalf("expected a reload from %s, got %v", MainConfigDebian, cmds)
		}
	})

	t.Run("flushes when the main config has no header", func(t *testing.T) {
		var cmds []string
		host := firewallExecHostStub{
			runRoot: func(cmd string) error {
				if cmd == flushCheckCmd(MainConfigDebian) {
					return errors.New("absent")
				}
				return nil
			},
			runRootWithOutput: func(cmd string) (string, error) {
				cmds = append(cmds, cmd)
				return "", nil
			},
		}
		if err := RestoreManagedRuleset(host, snap, MainConfigDebian); err != nil {
			t.Fatalf("RestoreManagedRuleset failed: %v", err)
		}
		if !containsCmd(cmds, FlushLine) || !containsCmd(cmds, "nft -f -") {
			t.Fatalf("expected a flushed reload, got %v", cmds)
		}
	})

	t.Run("flushes when the main config is gone", func(t *testing.T) {
		var cmds []string
		host := firewallExecHostStub{
			runRootWithOutput: func(cmd string) (string, error) {
				cmds = append(cmds, cmd)
				if strings.HasPrefix(cmd, "if test -f ") {
					return "HL:absent", nil
				}
				return "", nil
			},
		}
		if err := RestoreManagedRuleset(host, snap, MainConfigDebian); err != nil {
			t.Fatalf("RestoreManagedRuleset failed: %v", err)
		}
		if !containsCmd(cmds, "nft flush ruleset") {
			t.Fatalf("expected the loaded ruleset to be flushed, got %v", cmds)
		}
	})

	t.Run("requires a host", func(t *testing.T) {
		if err := RestoreManagedRuleset(nil, snap, MainConfigDebian); err == nil {
			t.Fatal("expected a host to be required")
		}
	})
}

func TestRollbackRefusesToFlushOnAnUnreadableProbe(t *testing.T) {
	snap := pluginapi.FileSnapshot{Path: testDest, Existed: false}

	for _, tc := range []struct {
		name string
		out  string
		err  error
		want string
	}{
		{name: "transport failure", err: errors.New("connection lost"), want: "probe " + MainConfigDebian},
		{name: "unrecognized answer", out: "sudo: a password is required", want: "unexpected answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cmds []string
			host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
				cmds = append(cmds, cmd)
				if strings.HasPrefix(cmd, "if test -f ") {
					return tc.out, tc.err
				}
				return "", nil
			}}
			err := RestoreManagedRuleset(host, snap, MainConfigDebian)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
			if containsCmd(cmds, "nft flush ruleset") {
				t.Fatalf("a probe that did not answer must not flush the host ruleset, got %v", cmds)
			}
		})
	}
}

func TestRollbackReportsAFailedReload(t *testing.T) {
	snap := pluginapi.FileSnapshot{Path: testDest, Existed: false}

	cases := []struct {
		name   string
		absent bool
		out    string
		want   string
	}{
		{
			name: "names what nft complained about",
			out:  "/etc/nftables.conf:3:1-5: Error: syntax error",
			want: "syntax error",
		},
		{
			name: "falls back to the exit status when nft said nothing",
			want: "reload " + MainConfigDebian,
		},
		{
			name:   "reports a failed flush",
			absent: true,
			out:    "Error: Could not process rule",
			want:   "Could not process rule",
		},
		{
			name:   "reports a silent flush failure",
			absent: true,
			want:   "flush the loaded ruleset",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := firewallExecHostStub{
				runRootWithOutput: func(cmd string) (string, error) {
					if strings.HasPrefix(cmd, "if test -f ") {
						if tc.absent {
							return "HL:absent", nil
						}
						return "HL:present", nil
					}
					if strings.Contains(cmd, "nft ") {
						return tc.out, errors.New("exit 1")
					}
					return "", nil
				},
			}
			err := RestoreManagedRuleset(host, snap, MainConfigDebian)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRollbackStopsWhenTheFileCannotBeRestored(t *testing.T) {
	host := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return "regular file|644|root|root|4", nil
		},
		writeRootFile: func(string, []byte, os.FileMode) error {
			return errors.New("read-only filesystem")
		},
	}
	snap := pluginapi.FileSnapshot{Path: testDest, Existed: true, Mode: "644", Owner: "root", Group: "root", ContentB64: "dGVzdA=="}

	err := RestoreManagedRuleset(host, snap, MainConfigDebian)
	if err == nil || !strings.Contains(err.Error(), "read-only filesystem") {
		t.Fatalf("expected the restore failure, got %v", err)
	}
}

func TestListenPortReadsTheAddressForms(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{in: "0.0.0.0:22", want: 22, ok: true},
		{in: "[::]:2222", want: 2222, ok: true},
		{in: "*:22", want: 22, ok: true},
		{in: "/run/sshd.sock"},
		{in: "0.0.0.0:ssh"},
		{in: "0.0.0.0:0"},
		{in: "0.0.0.0:70000"},
	}

	for _, tc := range cases {
		got, ok := listenPort(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("listenPort(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func containsCmd(cmds []string, want string) bool {
	for _, cmd := range cmds {
		if strings.Contains(cmd, want) {
			return true
		}
	}
	return false
}

func TestSSHDListeningPortsCoversSocketActivation(t *testing.T) {
	t.Run("a socket unit's live port counts", func(t *testing.T) {
		host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
			switch {
			case strings.HasPrefix(cmd, "ss -Hltnp"):
				return `LISTEN 0 4096 *:22 *:* users:(("systemd",pid=1,fd=52))`, nil
			case strings.Contains(cmd, "ssh.socket"):
				return "[::]:22 (Stream)\n", nil
			}
			return "", nil
		}}

		ports, err := sshdListeningPorts(host)
		if err != nil {
			t.Fatalf("sshdListeningPorts failed: %v", err)
		}
		if len(ports) != 1 || ports[0] != 22 {
			t.Fatalf("expected the socket-activated port, got %v", ports)
		}
	})

	t.Run("a declared port nothing listens on does not count", func(t *testing.T) {
		host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
			switch {
			case strings.HasPrefix(cmd, "ss -Hltnp"):
				return `LISTEN 0 4096 *:22 *:* users:(("systemd",pid=1,fd=52))`, nil
			case strings.Contains(cmd, "ssh.socket"):
				return "[::]:2222 (Stream)\n", nil
			}
			return "", nil
		}}

		if ports, err := sshdListeningPorts(host); err == nil {
			t.Fatalf("expected a refusal rather than %v", ports)
		}
	})
}

func TestRollbackRemovesOnlyTheFlushLineItAdded(t *testing.T) {
	const other = `include "/etc/nftables.d/50-other.nft"`
	current := FlushLine + "\n\n" + other + "\n"

	var wrote string
	host := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
		writeRootFile: func(_ string, data []byte, _ os.FileMode) error {
			wrote = string(data)
			return nil
		},
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        FlushLine,
		FileExisted: true,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if strings.Contains(wrote, FlushLine) {
		t.Fatalf("expected the flush header to be gone, got %q", wrote)
	}
	if !strings.Contains(wrote, other) {
		t.Fatalf("expected the other profile's include to survive, got %q", wrote)
	}
}

func TestRollbackKeepsTheFlushWhileAnotherManagedIncludeRemains(t *testing.T) {
	const other = `include "/etc/nftables.d/99-hardline-other.nft"`
	current := FlushLine + "\n" + other + "\n"

	host := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
		writeRootFile: func(string, []byte, os.FileMode) error {
			t.Fatal("the flush header must stay while another profile's ruleset is still included")
			return nil
		},
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        FlushLine,
		FileExisted: true,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
}

func TestRollbackKeepsAMainConfigAnotherProfileStillUses(t *testing.T) {
	const mine = "/etc/nftables.d/99-hardline-firewall.nft"
	const other = `include "/etc/nftables.d/99-hardline-other.nft"`
	current := FlushLine + "\n" + IncludeLine(mine) + "\n" + other + "\n"

	var wrote string
	var cmds []string
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
		runRootWithOutput: func(cmd string) (string, error) {
			cmds = append(cmds, cmd)
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile:  func(string) (string, error) { return current, nil },
		writeRootFile: func(_ string, data []byte, _ os.FileMode) error { wrote = string(data); return nil },
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        IncludeLine(mine),
		FileExisted: false,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, "rm -f ") {
			t.Fatalf("a main config another profile includes from must survive, got %v", cmds)
		}
	}
	if strings.Contains(wrote, mine) {
		t.Fatalf("expected this profile's include to be gone, got %q", wrote)
	}
	if !strings.Contains(wrote, other) {
		t.Fatalf("expected the other profile's include to survive, got %q", wrote)
	}
}

func TestRollbackRemovesAMainConfigNoOtherProfileUses(t *testing.T) {
	const mine = "/etc/nftables.d/99-hardline-firewall.nft"
	current := FlushLine + "\n" + IncludeLine(mine) + "\n"

	var cmds []string
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		},
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
	}

	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        IncludeLine(mine),
		FileExisted: false,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if !containsCmd(cmds, "rm -f "+pluginapi.ShellArg(MainConfigDebian)) {
		t.Fatalf("expected the main config this run created to be removed, got %v", cmds)
	}
}

func TestRollbackKeepsAFlushLineHardlineDidNotWrite(t *testing.T) {
	current := FlushLine + "\n"
	host := firewallExecHostStub{
		runRoot: func(cmd string) error {
			if cmd == flushMarkerCheckCmd(MainConfigDebian) {
				return errors.New("no marker")
			}
			return nil
		},
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(current)), nil
		},
		readRootFile: func(string) (string, error) { return current, nil },
		writeRootFile: func(string, []byte, os.FileMode) error {
			t.Fatal("a flush line hardline never wrote is the operator's, not hardline's to remove")
			return nil
		},
	}
	err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        FlushLine,
		FileExisted: true,
		Added:       true,
	})
	if err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
}

// The profile that writes the flush header is rarely the profile that rolls back last, so removal
// has to follow the file's state rather than which run recorded Added.
func TestRollbackRemovesTheFlushWhicheverProfileGoesLast(t *testing.T) {
	const mine = "/etc/nftables.d/99-hardline-firewall.nft"
	const other = "/etc/nftables.d/99-hardline-other.nft"

	newHost := func(t *testing.T, content *string) firewallExecHostStub {
		t.Helper()
		return firewallExecHostStub{
			runRootWithOutput: func(string) (string, error) {
				return fmt.Sprintf("regular file|644|root|root|%d", len(*content)), nil
			},
			readRootFile: func(string) (string, error) { return *content, nil },
			writeRootFile: func(_ string, data []byte, _ os.FileMode) error {
				*content = string(data)
				return nil
			},
		}
	}

	// This profile wrote the header, but the other profile's ruleset still loads through it.
	content := FlushMarker + "\n" + FlushLine + "\n" + IncludeLine(other) + "\n"
	kept := content
	if err := RestoreNftablesInclude(newHost(t, &content), pluginapi.ConfigLineSnapshot{
		Path: MainConfigDebian, Line: FlushLine, FileExisted: true, Added: true,
	}); err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if content != kept {
		t.Fatalf("the header must stay while another managed include needs it, got %q", content)
	}

	// The other profile goes last. Its own record says it found the header already there, and
	// rollback walks its include out before its flush, the way the capture order gives them back.
	content = FlushMarker + "\n" + FlushLine + "\n" + IncludeLine(mine) + "\n"
	host := newHost(t, &content)
	if err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path: MainConfigDebian, Line: IncludeLine(mine), FileExisted: true, Added: true,
	}); err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if err := RestoreNftablesInclude(host, pluginapi.ConfigLineSnapshot{
		Path: MainConfigDebian, Line: FlushLine, FileExisted: true, Added: false,
	}); err != nil {
		t.Fatalf("RestoreNftablesInclude failed: %v", err)
	}
	if strings.Contains(content, FlushLine) || strings.Contains(content, FlushMarker) {
		t.Fatalf("the last profile out has to take the header with it, got %q", content)
	}
}

func TestFlushLineConflictIsReported(t *testing.T) {
	rec := pluginapi.ConfigLineSnapshot{
		Path:        MainConfigDebian,
		Line:        FlushLine,
		FileExisted: true,
		Added:       false,
	}
	gone := firewallExecHostStub{runRoot: func(cmd string) error {
		if cmd == flushCheckCmd(MainConfigDebian) {
			return errors.New("absent")
		}
		return nil
	}}
	conflicts := includeLineConflict(gone, rec)
	if len(conflicts) != 1 || !strings.Contains(conflicts[0], FlushLine) {
		t.Fatalf("expected a removed-flush conflict, got %v", conflicts)
	}
	if got := includeLineConflict(firewallExecHostStub{}, rec); got != nil {
		t.Fatalf("expected no conflict while the flush header is present, got %v", got)
	}
}

func TestRemoveNftablesFlushEdgeCases(t *testing.T) {
	if err := RemoveNftablesFlush(nil, MainConfigDebian); err == nil {
		t.Fatal("expected a host to be required")
	}
	if err := RemoveNftablesFlush(firewallExecHostStub{}, "/etc/evil.conf"); err == nil {
		t.Fatal("expected a foreign main config to be refused")
	}
	if flushPresent(nil, MainConfigDebian) {
		t.Fatal("no host means nothing can be confirmed present")
	}

	absent := firewallExecHostStub{runRootWithOutput: func(string) (string, error) { return "", nil }}
	if err := RemoveNftablesFlush(absent, MainConfigDebian); err != nil {
		t.Fatalf("expected an absent main config to be a no-op, got %v", err)
	}

	const content = "include \"/etc/nftables.d/50-other.nft\"\n"
	untouched := firewallExecHostStub{
		runRootWithOutput: func(string) (string, error) {
			return fmt.Sprintf("regular file|644|root|root|%d", len(content)), nil
		},
		readRootFile: func(string) (string, error) { return content, nil },
		writeRootFile: func(string, []byte, os.FileMode) error {
			t.Fatal("a config with no flush header must not be rewritten")
			return nil
		},
	}
	if err := RemoveNftablesFlush(untouched, MainConfigDebian); err != nil {
		t.Fatalf("expected a no-op, got %v", err)
	}
}

func normalizedTestSpec(t *testing.T, spec *Spec) NormalizedSpec {
	t.Helper()
	normalized, err := NormalizeDesiredSpec(spec)
	if err != nil {
		t.Fatalf("NormalizeDesiredSpec failed: %v", err)
	}
	return normalized
}

func TestActivateFirewallLoadsAndVerifies(t *testing.T) {
	desired := normalizedTestSpec(t, validDeterministicFirewallSpec())

	var cmds []string
	host := firewallExecHostStub{
		runRootWithOutput: func(cmd string) (string, error) {
			cmds = append(cmds, cmd)
			return "", nil
		},
	}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("ActivateFirewall failed: %v", err)
	}

	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "nft -f '"+MainConfigDebian+"'") {
		t.Fatalf("expected the main config to be loaded in one transaction, got %v", cmds)
	}
	if strings.Contains(joined, "systemctl restart") {
		t.Fatalf("activation must not restart the service: its stop flushes the ruleset, got %v", cmds)
	}
}

func TestActivateFirewallRefusesAnIncompleteLoad(t *testing.T) {
	desired := normalizedTestSpec(t, validDeterministicFirewallSpec())

	host := firewallExecHostStub{liveRulesetJSON: `{"nftables":[]}`}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "not what was applied") {
		t.Fatalf("expected the read-back to refuse the load, got %v", err)
	}
	if !strings.Contains(err.Error(), "tcp dport 22 accept") {
		t.Fatalf("expected the missing rule to be named, got %v", err)
	}
}

func TestActivateFirewallReportsWhatNftSaid(t *testing.T) {
	desired := normalizedTestSpec(t, validDeterministicFirewallSpec())

	host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "nft -f ") {
			return "/etc/nftables.conf:9:1-6: Error: Could not process rule: No such file or directory", errors.New("exit status 1")
		}
		return "", nil
	}}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "No such file or directory") {
		t.Fatalf("expected nft's own complaint, got %v", err)
	}
}

func TestActivateFirewallRefusesToLockItselfOut(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{{Chain: "input", Proto: "tcp", Port: 8080, Action: "accept"}}
	desired := normalizedTestSpec(t, spec)

	var cmds []string
	host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		cmds = append(cmds, cmd)
		return "", nil
	}}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected a lockout refusal, got %v", err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "nft -f ") {
		t.Fatalf("nothing may be loaded once a lockout is detected, got %v", cmds)
	}
}

func TestActivateFirewallRefusesAnOutputPolicyThatDropsReplies(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = append(spec.Policies, Policy{Chain: "output", Policy: "drop"})
	desired := normalizedTestSpec(t, spec)

	var cmds []string
	host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		cmds = append(cmds, cmd)
		return "", nil
	}}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "answer an established connection") {
		t.Fatalf("expected an output-chain lockout refusal, got %v", err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "nft -f ") {
		t.Fatalf("nothing may be loaded once a lockout is detected, got %v", cmds)
	}
}

func TestActivateFirewallAcceptsAnOutputPolicyThatKeepsReplies(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = append(spec.Policies, Policy{Chain: "output", Policy: "drop"})
	spec.Rules = append(spec.Rules, Rule{Chain: "output", CTStates: []string{"established", "related"}, Action: "accept"})
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{liveRulesetJSON: liveRulesetJSON(desired)}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("expected the ruleset to be loaded, got %v", err)
	}
}

func TestSingleHostPrefixesReadBackAsTheKernelSpellsThem(t *testing.T) {
	for raw, want := range map[string]string{
		"10.0.0.1/32":     "10.0.0.1",
		"2001:db8::1/128": "2001:db8::1",
		"10.0.0.0/8":      "10.0.0.0/8",
		"2001:db8::/64":   "2001:db8::/64",
	} {
		got, err := normalizeAddress("source", raw)
		if err != nil {
			t.Fatalf("normalizeAddress(%q): %v", raw, err)
		}
		if got != want {
			t.Fatalf("normalizeAddress(%q) = %q, want %q; nft reads a single-host prefix back bare", raw, got, want)
		}
	}
}

func TestActivateFirewallRefusesAnEphemeralOutputDropAheadOfTheAccept(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = append(spec.Policies, Policy{Chain: "output", Policy: "accept"})
	spec.Rules = append(spec.Rules,
		Rule{Chain: "output", Proto: "tcp", Port: 40000, Action: "drop"},
		Rule{Chain: "output", CTStates: []string{"established"}, Action: "accept"},
	)
	desired := normalizedTestSpec(t, spec)

	err := ActivateFirewall(firewallExecHostStub{}, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "established reply") {
		t.Fatalf("a drop on a port a client could be answering from must be refused, got %v", err)
	}
}

func TestActivateFirewallAllowsAnOutputDropOnAServicePort(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = append(spec.Policies, Policy{Chain: "output", Policy: "accept"})
	spec.Rules = append(spec.Rules, Rule{Chain: "output", Proto: "tcp", Port: 25, Action: "drop"})
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{liveRulesetJSON: liveRulesetJSON(desired)}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("blocking outbound smtp cannot sever an ssh reply, got %v", err)
	}
}

func TestActivateFirewallRefusesWhenOnlyOneSSHListenerSurvives(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "ss -Hltnp") {
			return `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=800,fd=3))` + "\n" +
				`LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=800,fd=4))`, nil
		}
		return "", nil
	}}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected an accepted port 22 not to excuse a blocked port 2222, got %v", err)
	}
	if !strings.Contains(err.Error(), "port 2222") {
		t.Fatalf("expected the blocked listener to be named, got %v", err)
	}
}

func TestActivateFirewallAcceptsANonStandardSSHPort(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{{Chain: "input", Proto: "tcp", Port: 2222, Action: "accept"}}
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{
		runRootWithOutput: func(cmd string) (string, error) {
			if strings.HasPrefix(cmd, "ss -Hltnp") {
				return `LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=800,fd=3))`, nil
			}
			return "", nil
		},
		liveRulesetJSON: liveRulesetJSON(desired),
	}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("expected the ruleset to be loaded, got %v", err)
	}
}

func TestActivateFirewallIgnoresANarrowedAccept(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{{Chain: "input", Proto: "tcp", Port: 22, Source: "10.0.0.0/8", Action: "accept"}}
	desired := normalizedTestSpec(t, spec)

	err := ActivateFirewall(firewallExecHostStub{}, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected a narrowed accept to be refused as management access, got %v", err)
	}
}

func TestActivateFirewallRefusesAnAcceptTheChainNeverReaches(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{
		{Chain: "input", Proto: "tcp", Port: 22, Action: "drop"},
		{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
	}
	desired := normalizedTestSpec(t, spec)

	var cmds []string
	host := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		cmds = append(cmds, cmd)
		return "", nil
	}}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected the earlier drop to be honoured, got %v", err)
	}
	if !strings.Contains(err.Error(), "tcp dport 22 drop") {
		t.Fatalf("expected the blocking rule to be named, got %v", err)
	}
	if strings.Contains(strings.Join(cmds, "\n"), "nft -f ") {
		t.Fatalf("nothing may be loaded once a lockout is detected, got %v", cmds)
	}
}

func TestActivateFirewallRefusesAnEstablishedOnlyAccept(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{
		{Chain: "input", Proto: "tcp", Port: 22, CTStates: []string{"established"}, Action: "accept"},
	}
	desired := normalizedTestSpec(t, spec)

	err := ActivateFirewall(firewallExecHostStub{}, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected an accept that no new connection reaches to be refused, got %v", err)
	}
}

func TestActivateFirewallRefusesADropRuleUnderAnAcceptPolicy(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = []Policy{{Chain: "input", Policy: "accept"}}
	spec.Rules = []Rule{{Chain: "input", Proto: "tcp", Port: 22, Action: "drop"}}
	desired := normalizedTestSpec(t, spec)

	err := ActivateFirewall(firewallExecHostStub{}, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "lock itself out") {
		t.Fatalf("expected a drop rule to be caught under an accept policy, got %v", err)
	}
}

func TestActivateFirewallRefusesAScopedDropItCannotEvaluate(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{
		{Chain: "input", Proto: "tcp", Port: 22, Source: "10.0.0.0/8", Action: "drop"},
		{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
	}
	desired := normalizedTestSpec(t, spec)

	err := ActivateFirewall(firewallExecHostStub{}, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "cannot tell whether it covers this run's connection") {
		t.Fatalf("expected an unevaluable drop to be refused, got %v", err)
	}
}

func TestActivateFirewallAcceptsAnAcceptAheadOfANarrowerDrop(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Rules = []Rule{
		{Chain: "input", InInterface: "lo", Action: "accept"},
		{Chain: "input", CTStates: []string{"invalid"}, Action: "drop"},
		{Chain: "input", CTStates: []string{"established", "related"}, Action: "accept"},
		{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
		{Chain: "input", Proto: "tcp", Port: 22, Source: "10.0.0.0/8", Action: "drop"},
	}
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{liveRulesetJSON: liveRulesetJSON(desired)}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("expected the accept that comes first to settle the verdict, got %v", err)
	}
}

func TestActivateFirewallFailsClosedWithoutAnSSHProbe(t *testing.T) {
	desired := normalizedTestSpec(t, validDeterministicFirewallSpec())

	host := firewallExecHostStub{noSSHD: true}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "could not determine which port sshd") {
		t.Fatalf("expected the probe to fail closed, got %v", err)
	}

	failing := firewallExecHostStub{runRootWithOutput: func(cmd string) (string, error) {
		if strings.HasPrefix(cmd, "ss -Hltnp") {
			return "", errors.New("ss: command not found")
		}
		return "", nil
	}}
	if err := ActivateFirewall(failing, MainConfigDebian, desired); err == nil {
		t.Fatal("expected a failing probe to refuse the load")
	}
}

func TestActivateFirewallSkipsTheGuardForAnAcceptPolicy(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = []Policy{{Chain: "input", Policy: "accept"}}
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{noSSHD: true, liveRulesetJSON: liveRulesetJSON(desired)}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("expected an accept policy to need no lockout probe, got %v", err)
	}
}

func TestActivateFirewallLoadsAPortSpecificDropWithoutAnSSHProbe(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = []Policy{{Chain: "input", Policy: "accept"}}
	spec.Rules = []Rule{{Chain: "input", Proto: "tcp", Port: 445, Action: "drop"}}
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{noSSHD: true, liveRulesetJSON: liveRulesetJSON(desired)}
	if err := ActivateFirewall(host, MainConfigDebian, desired); err != nil {
		t.Fatalf("dropping an unrelated port under an accept policy cannot lock this host out, got %v", err)
	}
}

func TestActivateFirewallFailsClosedForAPortlessDropWithoutAnSSHProbe(t *testing.T) {
	spec := validDeterministicFirewallSpec()
	spec.Policies = []Policy{{Chain: "input", Policy: "accept"}}
	spec.Rules = []Rule{{Chain: "input", CTStates: []string{"new"}, Action: "drop"}}
	desired := normalizedTestSpec(t, spec)

	host := firewallExecHostStub{noSSHD: true, liveRulesetJSON: liveRulesetJSON(desired)}
	err := ActivateFirewall(host, MainConfigDebian, desired)
	if err == nil || !strings.Contains(err.Error(), "could not determine which port sshd") {
		t.Fatalf("a deny that names no port closes whatever port sshd is on, got %v", err)
	}
}

func TestActivateFirewallGuards(t *testing.T) {
	desired := normalizedTestSpec(t, validDeterministicFirewallSpec())
	if err := ActivateFirewall(nil, MainConfigDebian, desired); err == nil {
		t.Fatal("expected a host to be required")
	}
	if err := ActivateFirewall(firewallExecHostStub{}, "/etc/evil.conf", desired); err == nil {
		t.Fatal("expected a foreign main config to be refused")
	}
}

func TestDecodeNftValuesReadsACIDRPrefix(t *testing.T) {
	if got := DecodeNftStringValue([]byte(`{"prefix":{"addr":"10.0.0.0","len":8}}`)); got != "10.0.0.0/8" {
		t.Fatalf("masked address read back as %q, want 10.0.0.0/8", got)
	}
	if got := DecodeNftStringValue([]byte(`"10.0.0.1"`)); got != "10.0.0.1" {
		t.Fatalf("bare address read back as %q", got)
	}
	vals := DecodeNftStringValues([]byte(`{"set":[{"prefix":{"addr":"192.168.0.0","len":16}},"10.0.0.1"]}`))
	if len(vals) != 2 || vals[0] != "10.0.0.1" || vals[1] != "192.168.0.0/16" {
		t.Fatalf("set of addresses read back as %#v", vals)
	}
}
