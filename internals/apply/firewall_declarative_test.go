package apply

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/karvashish/hardline/pkg/profile"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestNormalizeDesiredFirewallSpec(t *testing.T) {
	spec, err := normalizeDesiredFirewallSpec(&profile.FirewallSpec{
		Backend:     "nftables",
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []profile.FirewallPolicy{
			{Chain: "input", Policy: "drop"},
			{Chain: "output", Policy: "accept"},
		},
		Rules: []profile.FirewallRule{
			{
				Chain:       "input",
				Proto:       "tcp",
				Port:        22,
				Source:      "10.0.0.0/24",
				InInterface: "eth0",
				Action:      "accept",
			},
			{
				Chain:  "input",
				Proto:  "tcp",
				Port:   443,
				Action: "accept",
			},
		},
	})
	if err != nil {
		t.Fatalf("normalizeDesiredFirewallSpec failed: %v", err)
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

func TestNormalizeCurrentFirewallState(t *testing.T) {
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
	state, err := normalizeCurrentFirewallState(nftJSON, "inet", "filter")
	if err != nil {
		t.Fatalf("normalizeCurrentFirewallState failed: %v", err)
	}
	if state.Policies["input"] != "drop" {
		t.Fatalf("expected input policy=drop, got %#v", state.Policies)
	}
	if len(state.Rules) != 2 {
		t.Fatalf("expected 2 normalized rules from set dport expression, got %d", len(state.Rules))
	}
	for _, rule := range state.Rules {
		if rule.InInterface != "eth0" || rule.Source != "10.0.0.0/24" || rule.Proto != "tcp" || rule.Action != "accept" {
			t.Fatalf("unexpected normalized rule: %+v", rule)
		}
	}
}

func TestDiffNormalizedFirewall(t *testing.T) {
	current := normalizedFirewallSpec{
		Family:   "inet",
		Table:    "filter",
		Policies: map[string]string{"input": "accept"},
		Rules: []normalizedFirewallRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 22},
		},
	}
	desired := normalizedFirewallSpec{
		Family:   "inet",
		Table:    "filter",
		Policies: map[string]string{"input": "drop"},
		Rules: []normalizedFirewallRule{
			{Chain: "input", Action: "accept", Proto: "tcp", Port: 443},
		},
	}

	diff := diffNormalizedFirewall(current, desired)
	if len(diff.PolicyChanges) != 1 {
		t.Fatalf("expected one policy change, got %#v", diff.PolicyChanges)
	}
	if len(diff.RulesToAdd) != 1 || diff.RulesToAdd[0].Port != 443 {
		t.Fatalf("unexpected rules to add: %#v", diff.RulesToAdd)
	}
	if len(diff.RulesToRemove) != 1 || diff.RulesToRemove[0].Port != 22 {
		t.Fatalf("unexpected rules to remove: %#v", diff.RulesToRemove)
	}
}

func TestHandleFirewallDeclarative(t *testing.T) {
	t.Run("unsupported backend", func(t *testing.T) {
		spec := validDeterministicFirewallSpec()
		spec.Backend = "ufw"
		err := handleFirewall(nil, spec)
		if err == nil || !strings.Contains(err.Error(), "unsupported firewall backend") {
			t.Fatalf("expected unsupported backend error, got %v", err)
		}
	})

	t.Run("missing managed destination", func(t *testing.T) {
		spec := validDeterministicFirewallSpec()
		spec.ManagedDest = ""
		err := handleFirewall(nil, spec)
		if err == nil || !strings.Contains(err.Error(), "managed_dest is required") {
			t.Fatalf("expected managed_dest required error, got %v", err)
		}
	})

	t.Run("mkdir error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error {
			return errors.New("mkdir failed")
		}
		err := handleFirewall(nil, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "mkdir -p") {
			t.Fatalf("expected mkdir error, got %v", err)
		}
	})

	t.Run("missing include is enabled during apply", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		spec := validDeterministicFirewallSpec()

		var cmds []string
		checkCount := 0
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			cmds = append(cmds, cmd)
			if cmd == firewallIncludeCheckCmd {
				checkCount++
				if checkCount == 1 {
					return errors.New("missing include")
				}
			}
			return nil
		}
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error { return nil }

		err := handleFirewall(nil, spec)
		if err != nil {
			t.Fatalf("handleFirewall failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")
		if !strings.Contains(joined, `printf '\ninclude "/etc/nftables.d/*.nft"\n' >> /etc/nftables.conf`) {
			t.Fatalf("expected include append command, got %#v", cmds)
		}
		if checkCount != 2 {
			t.Fatalf("expected include check before and after append, got %d", checkCount)
		}
	})

	t.Run("include enable failure is fatal", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		spec := validDeterministicFirewallSpec()

		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if cmd == firewallIncludeCheckCmd {
				return errors.New("missing include")
			}
			if strings.Contains(cmd, ">> /etc/nftables.conf") {
				return errors.New("append failed")
			}
			return nil
		}
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error {
			t.Fatal("writeRootFile should not run when include setup fails")
			return nil
		}

		err := handleFirewall(nil, spec)
		if err == nil || !strings.Contains(err.Error(), "ensure") {
			t.Fatalf("expected ensure include error, got %v", err)
		}
	})

	t.Run("new sftp client error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) {
			return nil, errors.New("sftp failed")
		}
		err := handleFirewall(nil, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "new sftp client") {
			t.Fatalf("expected sftp error, got %v", err)
		}
	})

	t.Run("write error", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		runRootCmd = func(_ *ssh.Client, _ string) error { return nil }
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, _ string, _ []byte, _ os.FileMode) error {
			return errors.New("write failed")
		}
		err := handleFirewall(nil, validDeterministicFirewallSpec())
		if err == nil || !strings.Contains(err.Error(), "remote.WriteRootFile") {
			t.Fatalf("expected write error, got %v", err)
		}
	})

	t.Run("success writes desired render and marks nftables dirty", func(t *testing.T) {
		restore := stubStepDeps()
		defer restore()
		var mkdirCmd string
		runRootCmd = func(_ *ssh.Client, cmd string) error {
			if strings.HasPrefix(cmd, "mkdir -p ") {
				mkdirCmd = cmd
			}
			return nil
		}
		newSFTPClient = func(_ *ssh.Client) (*sftp.Client, error) { return nil, nil }

		spec := validDeterministicFirewallSpec()
		desired, err := normalizeDesiredFirewallSpec(spec)
		if err != nil {
			t.Fatalf("normalizeDesiredFirewallSpec failed: %v", err)
		}
		wantRender := renderNormalizedFirewall(desired)
		writeRootFile = func(_ *ssh.Client, _ *sftp.Client, dest string, data []byte, mode os.FileMode) error {
			if dest != spec.ManagedDest {
				t.Fatalf("unexpected destination: %q", dest)
			}
			if string(data) != wantRender {
				t.Fatalf("unexpected rendered firewall data")
			}
			if mode != 0o644 {
				t.Fatalf("unexpected mode: %#o", mode)
			}
			return nil
		}

		err = handleFirewall(nil, spec)
		if err != nil {
			t.Fatalf("handleFirewall failed: %v", err)
		}
		if mkdirCmd == "" {
			t.Fatalf("expected mkdir command")
		}
		if !isServiceDirty("nftables") {
			t.Fatalf("expected nftables to be marked dirty")
		}
	})
}

func TestFirewallHelpers(t *testing.T) {
	t.Run("managed destination selection", func(t *testing.T) {
		if got := managedFirewallDestination(nil); got != "" {
			t.Fatalf("unexpected nil destination: %q", got)
		}
		if got := managedFirewallDestination(&profile.FirewallSpec{ManagedDest: "/etc/nftables.d/99-hardline-managed.nft"}); got != "/etc/nftables.d/99-hardline-managed.nft" {
			t.Fatalf("unexpected managed destination: %q", got)
		}
	})

	t.Run("policy and chain normalization errors", func(t *testing.T) {
		if _, err := normalizeFirewallPolicy("allow"); err == nil {
			t.Fatalf("expected invalid policy error")
		}
		if _, err := normalizeFirewallChain("weird"); err == nil {
			t.Fatalf("expected invalid chain error")
		}
	})

	t.Run("desired rule normalization errors", func(t *testing.T) {
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "icmp", Port: 22, Action: "accept"}); err == nil {
			t.Fatalf("expected icmp port validation error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "tcp"}); err == nil {
			t.Fatalf("expected missing port error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "tcp", Port: 70000}); err == nil {
			t.Fatalf("expected invalid port error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", CTStates: []string{"bogus"}, Action: "accept"}); err == nil {
			t.Fatalf("expected invalid ct state error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Action: "accept"}); err == nil {
			t.Fatalf("expected missing matcher error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "tcp", Port: 22, Action: "allow"}); err == nil {
			t.Fatalf("expected invalid action error")
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"}); err != nil {
			t.Fatalf("expected valid deterministic rule, got %v", err)
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", Proto: "icmp", Action: "accept"}); err != nil {
			t.Fatalf("expected valid icmp rule, got %v", err)
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", InInterface: "lo", Action: "accept"}); err != nil {
			t.Fatalf("expected valid interface-only rule, got %v", err)
		}
		if _, err := normalizeDesiredFirewallRule(profile.FirewallRule{Chain: "input", CTStates: []string{"related", "established"}, Action: "accept"}); err != nil {
			t.Fatalf("expected valid ct-state rule, got %v", err)
		}
	})

	t.Run("desired spec invalid required fields", func(t *testing.T) {
		bad := validDeterministicFirewallSpec()
		bad.Family = ""
		if _, err := normalizeDesiredFirewallSpec(bad); err == nil {
			t.Fatalf("expected missing family error")
		}

		bad = validDeterministicFirewallSpec()
		bad.Table = ""
		if _, err := normalizeDesiredFirewallSpec(bad); err == nil {
			t.Fatalf("expected missing table error")
		}

		bad = validDeterministicFirewallSpec()
		bad.Policies = nil
		if _, err := normalizeDesiredFirewallSpec(bad); err == nil {
			t.Fatalf("expected missing policies error")
		}

		bad = validDeterministicFirewallSpec()
		bad.Policies = []profile.FirewallPolicy{{Chain: "", Policy: "drop"}}
		if _, err := normalizeDesiredFirewallSpec(bad); err == nil {
			t.Fatalf("expected missing policy chain error")
		}
	})

	t.Run("decode nft helpers", func(t *testing.T) {
		ports := decodeNftPortValues([]byte(`{"set":[22,443,"8443"]}`))
		if len(ports) != 3 {
			t.Fatalf("expected 3 ports from set, got %#v", ports)
		}
		ports = decodeNftPortValues([]byte(`22`))
		if len(ports) != 1 || ports[0] != 22 {
			t.Fatalf("expected scalar port parse, got %#v", ports)
		}
		if decodeNftStringValue([]byte(`"10.0.0.0/24"`)) != "10.0.0.0/24" {
			t.Fatalf("expected string decode")
		}
		if decodeNftStringValue([]byte(`22`)) != "" {
			t.Fatalf("expected non-string decode to return empty")
		}
		states := decodeNftStringValues([]byte(`{"set":["related","established"]}`))
		if len(states) != 2 || states[0] != "established" || states[1] != "related" {
			t.Fatalf("unexpected decoded ct states: %#v", states)
		}
		if got := decodeNftStringValue([]byte(`{"set":["icmp"]}`)); got != "icmp" {
			t.Fatalf("expected single set entry to decode as scalar, got %q", got)
		}
	})

	t.Run("normalize nft ct/interface/icmp rules", func(t *testing.T) {
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
    ]}}
  ]
}`
		state, err := normalizeCurrentFirewallState(nftJSON, "inet", "filter")
		if err != nil {
			t.Fatalf("normalizeCurrentFirewallState failed: %v", err)
		}
		if len(state.Rules) != 3 {
			t.Fatalf("expected 3 normalized rules, got %d (%#v)", len(state.Rules), state.Rules)
		}
		joined := make([]string, 0, len(state.Rules))
		for _, r := range state.Rules {
			joined = append(joined, r.key())
		}
		got := strings.Join(joined, "\n")
		if !strings.Contains(got, `|accept||0|||lo||`) {
			t.Fatalf("expected loopback rule, got %s", got)
		}
		if !strings.Contains(got, `|accept|icmp|0|||||`) {
			t.Fatalf("expected icmp rule, got %s", got)
		}
		if !strings.Contains(got, `|accept||0|||||established,related`) {
			t.Fatalf("expected ct-state rule, got %s", got)
		}
	})

	t.Run("render rule with interfaces and addresses", func(t *testing.T) {
		line := renderNormalizedFirewallRule("ip6", normalizedFirewallRule{
			Proto:        "tcp",
			Port:         443,
			Action:       "accept",
			Source:       "2001:db8::/64",
			Destination:  "2001:db8::1/128",
			InInterface:  "eth0",
			OutInterface: "eth1",
		})
		if !strings.Contains(line, `iif "eth0"`) || !strings.Contains(line, `oif "eth1"`) {
			t.Fatalf("expected interface qualifiers in rendered rule: %q", line)
		}
		if !strings.Contains(line, "ip6 saddr 2001:db8::/64") || !strings.Contains(line, "ip6 daddr 2001:db8::1/128") {
			t.Fatalf("expected ip6 address qualifiers in rendered rule: %q", line)
		}
	})
}

func validDeterministicFirewallSpec() *profile.FirewallSpec {
	return &profile.FirewallSpec{
		Backend:     "nftables",
		Family:      "inet",
		Table:       "filter",
		ManagedDest: "/etc/nftables.d/99-hardline-firewall.nft",
		Policies: []profile.FirewallPolicy{
			{Chain: "input", Policy: "drop"},
		},
		Rules: []profile.FirewallRule{
			{Chain: "input", Proto: "tcp", Port: 22, Action: "accept"},
		},
	}
}

const nftJSONPolicyDropWithSSH22 = `{
  "nftables": [
    {"table":{"family":"inet","name":"filter"}},
    {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","policy":"drop"}},
    {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
      {"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}},
      {"accept":null}
    ]}}
  ]
}`
