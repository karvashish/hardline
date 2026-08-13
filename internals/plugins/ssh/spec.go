// Package ssh owns the sshd policy drop-in: it renders the declared keywords,
// proves the candidate parses, activates it, and then reads the effective
// configuration back out of sshd.
//
// This is a plugin of its own rather than a template step plus a service reload
// because writing the file proves nothing. sshd reads its includes lexically
// and keeps the first value it obtains for most keywords, so a directive
// earlier in the main config silently shadows the drop-in; a Match block
// elsewhere can re-enable for some users what the drop-in denied globally; and
// a reload against a config that does not parse leaves the daemon running the
// old policy, or refusing to start on the next boot. The only honest
// confirmation is sshd -t before activation and sshd -T after it.
package ssh

// MatchContext is a connection the profile wants the effective policy checked
// under, passed to sshd -T -C. sshd requires all three to evaluate Match, so
// all three are required here rather than guessed.
type MatchContext struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	Address string `json:"addr"`
}

type Spec struct {
	// Path is the drop-in under /etc/ssh/sshd_config.d. First match wins in
	// that directory, so EnforceManagedPath requires a 00-hardline prefix.
	Path string `json:"path"`
	Mode string `json:"mode"`
	// Service is the sshd unit name, which is "ssh" on Debian and Ubuntu and
	// "sshd" on the RHEL family. The profile states it; the engine carries no
	// distribution knowledge.
	Service string `json:"service" jsonschema:"enum=ssh,enum=sshd"`
	// Settings are the keywords to write. Values are strings or integers; the
	// keyword whitelist decides which.
	Settings map[string]any `json:"settings"`
	// VerifyContexts are additional connections to re-check the effective
	// policy under, so a Match block cannot re-enable a denied keyword for
	// some users while the global check passes.
	VerifyContexts []MatchContext `json:"verify_contexts,omitempty"`
}
