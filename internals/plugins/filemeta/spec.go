package filemeta

// Immutable and AppendOnly are pointers so nil ("leave as-is") differs from false ("clear").
type Spec struct {
	Path       string `json:"path"`
	Mode       string `json:"mode,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Group      string `json:"group,omitempty"`
	Immutable  *bool  `json:"immutable,omitempty"`
	AppendOnly *bool  `json:"append_only,omitempty"`
}
