package service

type RestartPolicy struct {
	Type  string   `json:"type" jsonschema:"enum=always,enum=on_change"`
	Steps []string `json:"steps,omitempty"`
}

type Spec struct {
	Name          string         `json:"name"`
	Enabled       *bool          `json:"enabled,omitempty" jsonschema:"default=true"`
	State         string         `json:"state,omitempty" jsonschema:"enum=started,enum=stopped,enum=restarted,enum=reloaded,enum=reload-or-restart"`
	RestartPolicy *RestartPolicy `json:"restart_policy,omitempty"`
}
