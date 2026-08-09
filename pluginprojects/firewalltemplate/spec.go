package main

type AllowRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto" jsonschema:"enum=tcp,enum=udp"`
}

type Spec struct {
	Backend string `json:"backend" jsonschema:"enum=nftables"`
	// MainConfig is the file the host's nftables service loads; it differs per
	// distribution family, so the profile states it.
	MainConfig   string      `json:"main_config" jsonschema:"enum=/etc/nftables.conf,enum=/etc/sysconfig/nftables.conf"`
	Policy       string      `json:"policy" jsonschema:"enum=allow,enum=deny,enum=reject,enum=drop"`
	TemplateSrc  string      `json:"template_src"`
	TemplateDest string      `json:"template_dest"`
	Allow        []AllowRule `json:"allow"`
}
