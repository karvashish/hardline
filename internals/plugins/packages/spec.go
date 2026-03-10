package packages

type Spec struct {
	Update     bool     `json:"update"`
	Upgrade    bool     `json:"upgrade"`
	Autoremove bool     `json:"autoremove"`
	Install    []string `json:"install"`
	Purge      []string `json:"purge"`
}
