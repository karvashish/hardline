package firewall

import (
	"encoding/json"
	"fmt"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	// OverrideKeyAllowTCPPorts opens the listed TCP ports on the input chain
	// in addition to whatever rules the profile already declares. Profile authors
	// must list this key in allowed_overrides for it to be accepted.
	OverrideKeyAllowTCPPorts = "allow_tcp_ports"
	// OverrideKeyAllowUDPPorts is the UDP counterpart to OverrideKeyAllowTCPPorts.
	OverrideKeyAllowUDPPorts = "allow_udp_ports"
)

func applyFirewallOverrides(ctx pluginapi.Context, spec *Spec) error {
	if spec == nil || len(ctx.Overrides) == 0 {
		return nil
	}

	tcpPorts, err := decodeOverridePortList(ctx.Overrides, OverrideKeyAllowTCPPorts)
	if err != nil {
		return err
	}
	udpPorts, err := decodeOverridePortList(ctx.Overrides, OverrideKeyAllowUDPPorts)
	if err != nil {
		return err
	}

	for _, port := range tcpPorts {
		spec.Rules = append(spec.Rules, Rule{
			Chain:  "input",
			Proto:  "tcp",
			Port:   port,
			Action: "accept",
		})
	}
	for _, port := range udpPorts {
		spec.Rules = append(spec.Rules, Rule{
			Chain:  "input",
			Proto:  "udp",
			Port:   port,
			Action: "accept",
		})
	}
	return nil
}

func decodeOverridePortList(overrides map[string]json.RawMessage, key string) ([]int, error) {
	raw, ok := overrides[key]
	if !ok {
		return nil, nil
	}
	var ports []int
	if err := json.Unmarshal(raw, &ports); err != nil {
		return nil, fmt.Errorf("override %q must be a JSON array of integers: %w", key, err)
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("override %q contains invalid port %d", key, port)
		}
	}
	return ports, nil
}
