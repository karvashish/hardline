package firewalltemplate

type AllowRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto" jsonschema:"enum=tcp,enum=udp"`
}

type Spec struct {
	Backend      string      `json:"backend" jsonschema:"enum=nftables"`
	Policy       string      `json:"policy" jsonschema:"enum=allow,enum=deny,enum=reject,enum=drop"`
	TemplateSrc  string      `json:"template_src"`
	TemplateDest string      `json:"template_dest"`
	Allow        []AllowRule `json:"allow"`
}
