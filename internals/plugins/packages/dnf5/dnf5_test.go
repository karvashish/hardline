package dnf5

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/plugins/packages"
)

type previewHost struct {
	command string
	output  string
}

func (*previewHost) RunRoot(string) error { return nil }
func (*previewHost) RunRootWithTimeout(string, time.Duration) (string, error) {
	return "", nil
}
func (h *previewHost) RunRootWithOutput(command string) (string, error) {
	h.command = command
	return h.output, nil
}
func (*previewHost) Stat(string) (os.FileInfo, error)                { return nil, os.ErrNotExist }
func (*previewHost) ReadRootFile(string) (string, error)             { return "", nil }
func (*previewHost) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func TestAdapter(t *testing.T) {
	b := backend()
	if b.Name != "packages_dnf5" {
		t.Fatalf("backend name is %q", b.Name)
	}
	if !b.NamePattern.MatchString("ImageMagick") || !b.NamePattern.MatchString("glibc.i686") ||
		b.NamePattern.MatchString("tree;id") {
		t.Fatalf("unexpected rpm package-name rule: %s", b.NamePattern)
	}
	if !b.PinPattern.MatchString("tree-1.8.0-10.el9.x86_64") {
		t.Fatalf("unexpected rpm pin rule: %s", b.PinPattern)
	}
	if !strings.Contains(lockCheck, "/var/cache/libdnf5/*.pid") ||
		strings.Contains(lockCheck, "/var/cache/dnf/metadata_lock.pid") {
		t.Fatalf("dnf5 lock probe is wrong:\n%s", lockCheck)
	}
	if err := b.CheckLock(nil); err == nil {
		t.Fatal("a nil host must fail the lock check")
	}

	if want := packages.DNFCommands(); b.Commands != want {
		t.Fatalf("commands differ\n got: %+v\nwant: %+v", b.Commands, want)
	}

	host := &previewHost{output: "bash.x86_64  5.2-1  baseos\n"}
	upgrades, err := b.Previews.Upgrade(host)
	if err != nil || !slices.Equal(upgrades, []string{"bash"}) {
		t.Fatalf("upgrade preview packages=%v error=%v", upgrades, err)
	}
	if want := `LC_ALL=C dnf -q check-upgrade; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`; host.command != want {
		t.Fatalf("upgrade command=%q, want %q", host.command, want)
	}
	host.output = "Transaction Summary\n"
	if _, err := b.Previews.Install(host, []string{"tree"}); err != nil {
		t.Fatalf("dnf5 transaction proof was rejected: %v", err)
	}

	p := Plugin()
	if p.Name != "packages_dnf5" {
		t.Fatalf("plugin identity is wrong: name=%q", p.Name)
	}
}
