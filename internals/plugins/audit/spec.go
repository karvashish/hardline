package audit

type Spec struct {
	Src  string `json:"src"`
	Dest string `json:"dest"`
	Mode string `json:"mode"`
}
