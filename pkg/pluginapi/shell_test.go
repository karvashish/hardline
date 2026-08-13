package pluginapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var metacharacterCorpus = []string{
	"$(id -un)",
	"`id -un`",
	"${HOME}",
	"$HOME",
	"a;id",
	"a|id",
	"a&id",
	"a&&id",
	"a\nid",
	"a>out",
	"a<in",
	"a'b",
	`a"b`,
	`a\b`,
	"a*b",
	"a b",
}

var dashCorpus = []string{"--force", "-rf", "-"}

func TestShellArgNeutralizesMetacharacters(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "PWNED")
	t.Setenv("HOME", "/should-not-expand")

	for _, raw := range append(append([]string{}, metacharacterCorpus...), dashCorpus...) {
		payload := strings.ReplaceAll(raw, "id -un", "touch "+marker)
		payload = strings.ReplaceAll(payload, "id", "touch "+marker)

		out, err := exec.Command("/bin/sh", "-c", "printf %s "+ShellArg(payload)).Output()
		if err != nil {
			t.Fatalf("sh rejected quoted %q: %v", payload, err)
		}
		if string(out) != payload {
			t.Fatalf("ShellArg(%q) round-tripped as %q", payload, string(out))
		}
		if _, statErr := os.Stat(marker); statErr == nil {
			t.Fatalf("ShellArg(%q) allowed command substitution to execute", payload)
		}
	}
}

func TestEnforceManagedPathRejectsMetacharacters(t *testing.T) {
	for _, raw := range metacharacterCorpus {
		dest := "/etc/99-hardline" + raw + ".conf"
		if err := EnforceManagedPath(dest); err == nil {
			t.Fatalf("expected %q to be rejected", dest)
		}
	}

	for _, dest := range []string{
		"/etc/nftables.d/99-hardline.nft",
		"/etc/ssh/sshd_config.d/99-hardline.conf",
		"/etc/audit/rules.d/99-hardline-base.rules",
	} {
		if err := EnforceManagedPath(dest); err != nil {
			t.Fatalf("expected %q to pass, got %v", dest, err)
		}
	}
}
