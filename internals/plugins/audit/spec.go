// Package audit owns the Linux audit rule policy: it writes the rules file and
// then makes the kernel actually run it.
//
// This is a plugin of its own rather than a template step plus a service step
// because neither half works on a RHEL-family host. auditd.service sets
// RefuseManualStop, so a restart is refused, and its ExecReload only sends
// SIGHUP, which re-reads auditd.conf without touching rules.d. The supported
// control path is augenrules(8), and the only honest confirmation that a rule
// took effect is reading the loaded policy back with auditctl.
package audit

type Spec struct {
	// Src is the profile-relative rules file, declared in profile.json
	// templates[] like any other signed content.
	Src string `json:"src"`
	// Dest is the file under /etc/audit/rules.d that augenrules compiles.
	Dest string `json:"dest"`
	Mode string `json:"mode,omitempty"`
}
