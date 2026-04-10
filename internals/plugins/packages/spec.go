package packages

type Spec struct {
	Update     string   `json:"update,omitempty"`
	Upgrade    string   `json:"upgrade,omitempty"`
	Autoremove string   `json:"autoremove,omitempty"`
	Install    []string `json:"install"`
	Purge      []string `json:"purge"`
}
