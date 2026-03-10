package service

type Spec struct {
	Name    string `json:"name"`
	Enabled *bool  `json:"enabled,omitempty" jsonschema:"default=true"`
	State   string `json:"state,omitempty" jsonschema:"enum=started,enum=stopped,enum=restarted,enum=reloaded,enum=reload-or-restart"`
}
