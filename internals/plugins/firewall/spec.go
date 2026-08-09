package firewall

type Policy struct {
	Chain  string `json:"chain" jsonschema:"enum=input,enum=output,enum=forward"`
	Policy string `json:"policy" jsonschema:"enum=accept,enum=drop,enum=reject"`
}

type Rule struct {
	Chain        string   `json:"chain" jsonschema:"enum=input,enum=output,enum=forward"`
	Proto        string   `json:"proto"`
	Port         int      `json:"port"`
	Ports        []int    `json:"ports"`
	Source       string   `json:"source"`
	Destination  string   `json:"destination"`
	InInterface  string   `json:"in_interface"`
	OutInterface string   `json:"out_interface"`
	CTStates     []string `json:"ct_states"`
	Action       string   `json:"action" jsonschema:"enum=accept,enum=drop,enum=reject"`
}

type Spec struct {
	Backend string `json:"backend" jsonschema:"enum=nftables"`
	// MainConfig is the file the host's nftables service actually loads. It
	// differs per distribution family, so the profile states it rather than the
	// engine assuming Debian's location.
	MainConfig  string   `json:"main_config" jsonschema:"enum=/etc/nftables.conf,enum=/etc/sysconfig/nftables.conf"`
	Family      string   `json:"family" jsonschema:"enum=inet,enum=ip,enum=ip6"`
	Table       string   `json:"table"`
	ManagedDest string   `json:"managed_dest"`
	Policies    []Policy `json:"policies"`
	Rules       []Rule   `json:"rules"`
}
