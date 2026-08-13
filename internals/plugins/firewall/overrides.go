package firewall

import (
	"encoding/json"
	"fmt"
)

const (
	OverrideKeyAllowTCPPorts = "allow_tcp_ports"
	OverrideKeyAllowUDPPorts = "allow_udp_ports"
)

func applyFirewallOverrides(overrides map[string]json.RawMessage, spec *Spec) error {
	if spec == nil || len(overrides) == 0 {
		return nil
	}

	tcpPorts, err := decodeOverridePortList(overrides, OverrideKeyAllowTCPPorts)
	if err != nil {
		return err
	}
	udpPorts, err := decodeOverridePortList(overrides, OverrideKeyAllowUDPPorts)
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
