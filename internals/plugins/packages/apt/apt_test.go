package apt

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

type aptHost struct {
	commands *[]string
	output   string
	err      error
}

func (h aptHost) record(command string) {
	if h.commands != nil {
		*h.commands = append(*h.commands, command)
	}
}

func (h aptHost) RunRoot(command string) error {
	h.record(command)
	return h.err
}

func (h aptHost) RunRootWithTimeout(command string, _ time.Duration) (string, error) {
	h.record(command)
	return h.output, h.err
}

func (h aptHost) RunRootWithOutput(command string) (string, error) {
	h.record(command)
	return h.output, h.err
}

func (aptHost) Stat(string) (os.FileInfo, error)                { return nil, os.ErrNotExist }
func (aptHost) ReadRootFile(string) (string, error)             { return "", nil }
func (aptHost) WriteRootFile(string, []byte, os.FileMode) error { return nil }

func TestAdapter(t *testing.T) {
	b := backend()
	if b.Name != "packages_apt" {
		t.Fatalf("backend name is %q", b.Name)
	}
	if !b.NamePattern.MatchString("libssl3") || !b.NamePattern.MatchString("g++") ||
		b.NamePattern.MatchString("ImageMagick") || b.NamePattern.MatchString("curl;id") {
		t.Fatalf("unexpected Debian package-name rule: %s", b.NamePattern)
	}
	if !b.PinPattern.MatchString("libc6=2:2.36-9+deb12u10") ||
		b.PinPattern.MatchString("libc6=2.36 --force") {
		t.Fatalf("unexpected Debian pin rule: %s", b.PinPattern)
	}
	for _, path := range []string{
		"/var/lib/dpkg/lock", "/var/lib/apt/lists/lock", "/var/lib/dpkg/lock-frontend",
	} {
		if !strings.Contains(lockCheck, path) {
			t.Errorf("apt lock probe omits %q:\n%s", path, lockCheck)
		}
	}
	if err := b.CheckLock(nil); err == nil {
		t.Fatal("a nil host must fail the lock check")
	}

	wantCommands := packages.Commands{
		Update:     "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get update -y",
		Upgrade:    "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get upgrade -y",
		Install:    "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get install -y",
		Purge:      "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get purge -y",
		Autoremove: "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get autoremove -y",
	}
	if b.Commands != wantCommands {
		t.Fatalf("apt commands differ\n got: %+v\nwant: %+v", b.Commands, wantCommands)
	}
	if got := cmd("apt-get test"); got != "DEBIAN_FRONTEND=noninteractive timeout 1800 apt-get test" {
		t.Fatalf("cmd returned %q", got)
	}

	p := Plugin()
	if p.Name != "packages_apt" || !p.InternalValidation {
		t.Fatalf("plugin identity is wrong: name=%q validation=%v", p.Name, p.InternalValidation)
	}
}

func TestPreviews(t *testing.T) {
	const simulation = `Reading package lists...
Inst curl:amd64 [8.0] (8.1 Debian:12)
Inst libcurl4 [8.0] (8.1 Debian:12)
Remv telnet [1.0]
Purg telnet-common [1.0]
`
	var commands []string
	host := aptHost{commands: &commands, output: simulation}
	previews := backend().Previews

	upgrade, err := previews.Upgrade(host)
	if err != nil || !slices.Equal(upgrade, []string{"curl", "libcurl4"}) {
		t.Fatalf("upgrade packages=%v error=%v", upgrade, err)
	}
	installed, err := previews.Install(host, []string{"curl"})
	if err != nil || !slices.Equal(installed, []string{"curl", "libcurl4"}) {
		t.Fatalf("install packages=%v error=%v", installed, err)
	}
	autoremoved, err := previews.Autoremove(host)
	if err != nil || !slices.Equal(autoremoved, []string{"telnet", "telnet-common"}) {
		t.Fatalf("autoremove packages=%v error=%v", autoremoved, err)
	}
	purged, err := previews.Purge(host, []string{"telnet"})
	if err != nil || !slices.Equal(purged, []string{"telnet", "telnet-common"}) {
		t.Fatalf("purge packages=%v error=%v", purged, err)
	}

	for _, command := range commands {
		if !strings.HasPrefix(command, "LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -s ") {
			t.Errorf("parsed command is not locale-pinned: %q", command)
		}
	}
	if !strings.Contains(commands[1], "install 'curl'") || !strings.Contains(commands[3], "purge 'telnet'") {
		t.Fatalf("package arguments are missing: %v", commands)
	}
}

func TestPreviewErrors(t *testing.T) {
	boom := errors.New("preview failed")
	host := aptHost{err: boom}
	tests := []struct {
		name string
		run  func() error
	}{
		{"upgrade", func() error { _, err := upgradePreview(host); return err }},
		{"install", func() error { _, err := installPreview(host, []string{"curl"}); return err }},
		{"autoremove", func() error { _, err := autoremovePreview(host); return err }},
		{"purge", func() error { _, err := purgePreview(host, []string{"curl"}); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != boom {
				t.Fatalf("error=%v, want %v", err, boom)
			}
		})
	}
}

func TestParseSimulation(t *testing.T) {
	out := `translated prose
Inst
Inst :amd64 invalid
Inst curl:amd64 1
Inst curl:arm64 duplicate
Remv old 1
Purg config 1
`
	got := parseSimulation(out, "Inst ", "Remv ", "Purg ")
	if !slices.Equal(got, []string{"curl", "old", "config"}) {
		t.Fatalf("packages=%v", got)
	}
	if got := parseSimulation("Nothing to do.\n", "Inst "); got != nil {
		t.Fatalf("unrecognized prose became packages: %v", got)
	}
}

func TestQuery(t *testing.T) {
	if _, _, _, err := query(nil, "curl"); err == nil {
		t.Fatal("nil host was accepted")
	}
	boom := errors.New("transport failed")
	if _, _, _, err := query(aptHost{err: boom}, "curl"); err == nil || !strings.Contains(err.Error(), "transport failed") {
		t.Fatalf("transport error was lost: %v", err)
	}

	var commands []string
	host := aptHost{commands: &commands, output: "HL:install ok installed\t1.2.3-4\nHL-RC:0\n"}
	installed, version, pin, err := backend().Query(host, "curl")
	if err != nil || !installed || version != "1.2.3-4" || pin != "curl=1.2.3-4" {
		t.Fatalf("query=%v/%q/%q error=%v", installed, version, pin, err)
	}
	if len(commands) != 1 || !strings.Contains(commands[0], "dpkg-query -W") ||
		!strings.Contains(commands[0], "'curl'") || !strings.Contains(commands[0], "HL-RC") {
		t.Fatalf("query command is wrong: %v", commands)
	}
}

func TestClassifyDpkgProbe(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		installed bool
		version   string
		pin       string
		wantError string
	}{
		{"installed", "\nHL:install ok installed\t1.2.3\nHL-RC:0\n", true, "1.2.3", "curl=1.2.3", ""},
		{"not installed", "HL:unknown ok not-installed\t\nHL-RC:0\n", false, "", "", ""},
		{"config files", "HL:deinstall ok config-files\t1.0\nHL-RC:0\n", false, "", "", ""},
		{"unknown package", "dpkg-query: no packages found matching curl\nHL-RC:1\n", false, "", "", ""},
		{"missing completion", "HL:install ok installed\t1.2.3\n", false, "", "", "did not complete"},
		{"too many completions", "HL-RC:0\nHL-RC:0\n", false, "", "", "did not complete"},
		{"reported noise", "dpkg: database is locked\nHL-RC:2\n", false, "", "", "reported"},
		{"no status", "HL-RC:0\n", false, "", "", "returned no status"},
		{"malformed status", "HL:installed\t1.0\nHL-RC:0\n", false, "", "", "unexpected dpkg status"},
		{"error state", "HL:install reinstreq installed\t1.0\nHL-RC:0\n", false, "", "", "error state"},
		{"missing version", "HL:install ok installed\nHL-RC:0\n", false, "", "", "no version"},
		{"indeterminate state", "HL:install ok unpacked\t1.0\nHL-RC:0\n", false, "", "", "neither installed nor absent"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installed, version, pin, err := classifyDpkgProbe("curl", tc.output)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("error=%v, want one containing %q", err, tc.wantError)
				}
				return
			}
			if err != nil || installed != tc.installed || version != tc.version || pin != tc.pin {
				t.Fatalf("got %v/%q/%q error=%v", installed, version, pin, err)
			}
		})
	}
}

var _ pluginapi.Host = aptHost{}
