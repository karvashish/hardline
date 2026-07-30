package firewall

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/karvashish/hardline/pkg/pluginapi"
	"github.com/karvashish/hardline/pkg/profile"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDesiredSpec(t *testing.T) {
	spec, err := NormalizeDesiredSpec(&Spec{
		Backend:     "nftables",
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
	if rule.Key() == "" || rule.key() == "" {
		t.Fatalf("expected non-empty rule keys")
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
		NormalizedRule{Chain: "input", Proto: "icmpv6", Action: "accept"}.Key():   {},
		NormalizedRule{Chain: "input", InInterface: "lo", Action: "accept"}.Key(): {},
	}
	for _, rule := range state.Rules {
		if _, ok := want[rule.Key()]; !ok {
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
			if cmd == IncludeCheckCmd {
				calls++
				if calls == 1 {
					return errors.New("missing")
				}
			}
			return nil
		}})
		if err != nil {
			t.Fatalf("EnsureNftablesInclude failed: %v", err)
		}
		if calls != 2 {
			t.Fatalf("expected 2 include checks, got %d", calls)
		}

		err = EnsureNftablesInclude(firewallExecHostStub{runRoot: func(cmd string) error {
			if cmd == IncludeCheckCmd {
				return errors.New("missing")
			}
			if strings.Contains(cmd, ">> /etc/nftables.conf") {
				return errors.New("append fail")
			}
			return nil
		}})
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure error, got %v", err)
		}

		calledAppend := false
		err = EnsureNftablesInclude(firewallExecHostStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, ">> /etc/nftables.conf") {
				calledAppend = true
			}
			return nil
		}})
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
				if cmd == IncludeCheckCmd {
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
		if !strings.Contains(strings.Join(cmds, "\n"), `printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf`) {
			t.Fatalf("expected include append command, got %v", cmds)
		}

		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot: func(cmd string) error {
				if cmd == IncludeCheckCmd {
					return errors.New("missing")
				}
				if strings.Contains(cmd, ">> /etc/nftables.conf") {
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
		if err == nil || !strings.Contains(err.Error(), "write root file") {
			t.Fatalf("expected write error, got %v", err)
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

		err = Apply(pluginapi.Context{Host: firewallExecHostStub{
			runRoot:           func(string) error { return nil },
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
		if gotDest != validDeterministicFirewallSpec().ManagedDest || gotData != wantRender || gotMode != 0o644 {
			t.Fatalf("unexpected write payload: dest=%q mode=%#o", gotDest, gotMode)
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
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", Family: "inet"})
		if err == nil || !strings.Contains(err.Error(), "table is required") {
			t.Fatalf("expected table required error, got %v", err)
		}
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", Family: "inet", Table: "filter"})
		if err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
			t.Fatalf("expected managed_dest required error, got %v", err)
		}
		_, err = Plan(pluginapi.Context{Host: firewallRuntimeStub{}}, &Spec{Backend: "nftables", Family: "inet", Table: "filter", ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft"})
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

		if err := ValidateApply(firewallExecHostStub{runRoot: func(string) error { return nil }}); err != nil {
			t.Fatalf("ValidateApply failed: %v", err)
		}
		err = ValidateApply(firewallExecHostStub{runRoot: func(cmd string) error {
			if cmd == IncludeCheckCmd {
				return errors.New("missing")
			}
			return nil
		}})
		if err == nil || !strings.Contains(err.Error(), "missing include") {
			t.Fatalf("expected include error, got %v", err)
		}
		err = ValidateApply(firewallExecHostStub{runRoot: func(cmd string) error {
			if strings.Contains(cmd, "nft -c") {
				return errors.New("bad")
			}
			return nil
		}})
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

		vres, err := ValidatePlan(firewallRuntimeStub{include: false, configErr: errors.New("bad")})
		if err != nil {
			t.Fatalf("ValidatePlan failed: %v", err)
		}
		joined := strings.Join(vres.Details, "\n")
		if !strings.Contains(joined, "missing") || !strings.Contains(joined, "reports errors") {
			t.Fatalf("unexpected validate plan details: %s", joined)
		}
		vres, err = ValidatePlan(firewallRuntimeStub{include: true})
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
			runRoot:           func(string) error { return nil },
			runRootWithOutput: func(string) (string, error) { return "644", nil },
			readRootFile:      func(string) (string, error) { return "abc", nil },
		}}, "f", validDeterministicFirewallSpec())
		if err != nil {
			t.Fatalf("Capture failed: %v", err)
		}
		if rec.RollbackMode != "deterministic" || len(rec.Objects) != 2 {
			t.Fatalf("unexpected rollback record: %+v", rec)
		}
		// Reverse-ordered rollback restores the managed file first, so
		// nftables.conf must be the first object recorded.
		if rec.Objects[0].File == nil || rec.Objects[0].File.Path != NftablesMainConfigPath {
			t.Fatalf("expected %s captured first, got %+v", NftablesMainConfigPath, rec.Objects[0].File)
		}
		if rec.Objects[1].File == nil || rec.Objects[1].File.Path != ManagedDestination(validDeterministicFirewallSpec()) {
			t.Fatalf("expected managed destination captured second, got %+v", rec.Objects[1].File)
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
		if firewallIncludePresent(nil) {
			t.Fatalf("nil runtime should report missing include")
		}
		if !firewallIncludePresent(firewallRuntimeStub{include: true}) {
			t.Fatalf("expected include to be detected")
		}
		if err := firewallConfigTest(nil); err == nil || !strings.Contains(err.Error(), "host is required") {
			t.Fatalf("expected runtime-required error, got %v", err)
		}
		if err := firewallConfigTest(firewallRuntimeStub{configErr: errors.New("bad")}); err == nil || !strings.Contains(err.Error(), "bad") {
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
	configErr   error
	rulesetJSON string
	rulesetErr  error
	readContent string
	readErr     error
}

func (s firewallRuntimeStub) RunRoot(cmd string) error {
	switch cmd {
	case IncludeCheckCmd:
		if s.include {
			return nil
		}
		return errors.New("missing")
	case "nft -c -f /etc/nftables.conf >/dev/null 2>&1":
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
	runRootErr           error
	runRootWithOutput    string
	runRootWithOutputErr error
	readContent          string
	readErr              error
}

func (s firewallHelperRuntimeStub) RunRoot(string) error { return s.runRootErr }

func (s firewallHelperRuntimeStub) RunRootWithOutput(string) (string, error) {
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
	runRoot           func(string) error
	runRootWithOutput func(string) (string, error)
	readRootFile      func(string) (string, error)
	writeRootFile     func(string, []byte, os.FileMode) error
}

func (s firewallExecHostStub) RunRoot(cmd string) error {
	if s.runRoot == nil {
		return nil
	}
	return s.runRoot(cmd)
}

func (s firewallExecHostStub) RunRootWithOutput(cmd string) (string, error) {
	if s.runRootWithOutput == nil {
		return "", nil
	}
	return s.runRootWithOutput(cmd)
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

// TestRollbackRestoresNftablesMainConfig covers the mutation apply makes
// outside the managed destination: without it, rollback reports success while
// leaving the appended include behind.
func TestRollbackRestoresNftablesMainConfig(t *testing.T) {
	plug := Plugin()

	t.Run("restores prior content byte-for-byte", func(t *testing.T) {
		original := "table inet filter {}\n"
		var wrotePath string
		var wroteData []byte
		var wroteMode os.FileMode
		host := firewallExecHostStub{
			writeRootFile: func(p string, data []byte, mode os.FileMode) error {
				wrotePath, wroteData, wroteMode = p, data, mode
				return nil
			},
		}

		snap := pluginapi.FileSnapshot{
			Path:       NftablesMainConfigPath,
			Existed:    true,
			Mode:       "644",
			ContentB64: base64.StdEncoding.EncodeToString([]byte(original)),
		}
		if err := plug.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap}); err != nil {
			t.Fatalf("rollback failed: %v", err)
		}
		if wrotePath != NftablesMainConfigPath || string(wroteData) != original || wroteMode != 0o644 {
			t.Fatalf("unexpected restore: path=%q data=%q mode=%#o", wrotePath, wroteData, wroteMode)
		}
	})

	t.Run("deletes a file that did not exist before apply", func(t *testing.T) {
		var cmds []string
		host := firewallExecHostStub{runRoot: func(cmd string) error {
			cmds = append(cmds, cmd)
			return nil
		}}

		snap := pluginapi.FileSnapshot{Path: NftablesMainConfigPath, Existed: false}
		if err := plug.Rollback(host, pluginapi.ObjectRecord{Kind: pluginapi.ObjectFile, File: &snap}); err != nil {
			t.Fatalf("rollback failed: %v", err)
		}
		if len(cmds) != 1 || !strings.Contains(cmds[0], "rm -f") {
			t.Fatalf("expected a delete, got %#v", cmds)
		}
	})

	t.Run("refuses a path that is not the main config", func(t *testing.T) {
		if err := restoreNftablesMainConfig(firewallExecHostStub{}, pluginapi.FileSnapshot{Path: "/etc/passwd"}); err == nil {
			t.Fatal("expected a non-constant path to be refused")
		}
		if err := restoreNftablesMainConfig(nil, pluginapi.FileSnapshot{Path: NftablesMainConfigPath}); err == nil {
			t.Fatal("expected a nil host to be refused")
		}
	})
}
