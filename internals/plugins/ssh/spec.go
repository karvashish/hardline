package ssh

type MatchContext struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Address string `json:"addr"`
}

type Spec struct {
	Path           string         `json:"path"`
	Mode           string         `json:"mode"`
	Service        string         `json:"service" jsonschema:"enum=ssh,enum=sshd"`
	Settings       map[string]any `json:"settings"`
	VerifyContexts []MatchContext `json:"verify_contexts,omitempty"`
}
