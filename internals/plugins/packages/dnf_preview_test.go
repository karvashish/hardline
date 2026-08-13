package packages

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestDNFCommands(t *testing.T) {
	commands := DNFCommands()
	want := Commands{
		Update:         "timeout 1800 dnf -q -y makecache --refresh",
		Upgrade:        "timeout 1800 dnf -y upgrade",
		Install:        "timeout 1800 dnf -y install",
		Purge:          "timeout 1800 dnf -y remove",
		Autoremove:     "timeout 1800 dnf -y autoremove",
		RollbackRemove: "timeout 1800 dnf -y --setopt=clean_requirements_on_remove=False remove",
	}
	if commands != want {
		t.Fatalf("commands differ\n got: %+v\nwant: %+v", commands, want)
	}
}

func TestDNFUpgradePreviews(t *testing.T) {
	const dnf4Listing = `Last metadata expiration check: just now.
bash.x86_64  5.2-1  baseos
bash.x86_64  5.2-1  duplicate
.x86_64      1-1    invalid
short
Obsoleting Packages
grub2-tools.x86_64  2.06-80  baseos
    grub2-old.x86_64  2.06-70  @baseos
`
	const dnf5Listing = `Updating and loading repositories:
Repositories loaded.
bash.x86_64         5.2-1     baseos
kernel.x86_64       6.1-2     updates
bash.x86_64         5.2-1     duplicate
`

	tests := []struct {
		name        string
		previews    Previews
		wantCommand string
		output      string
		want        []string
	}{
		{
			"dnf4",
			DNF4Previews(),
			`LC_ALL=C dnf -q check-update; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`,
			dnf4Listing,
			[]string{"bash", "grub2-tools"},
		},
		{
			"dnf5",
			DNF5Previews(),
			`LC_ALL=C dnf -q check-upgrade; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`,
			dnf5Listing,
			[]string{"bash", "kernel"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var command string
			host := hostStub{runRootWithOutput: func(cmd string) (string, error) {
				command = cmd
				return tc.output, nil
			}}
			got, err := tc.previews.Upgrade(host)
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("packages=%v error=%v, want %v", got, err, tc.want)
			}
			if command != tc.wantCommand {
				t.Fatalf("upgrade command=%q, want %q", command, tc.wantCommand)
			}
		})
	}

	bareBanner := hostStub{runRootWithOutput: func(string) (string, error) {
		return "Updating and loading repositories:\nRepositories loaded.\n", nil
	}}
	if got, err := DNF5Previews().Upgrade(bareBanner); err != nil || got != nil {
		t.Fatalf("dnf5 bare banner packages=%v error=%v", got, err)
	}

	boom := errors.New("check failed")
	host := hostStub{runRootWithOutput: func(string) (string, error) { return "ignored", boom }}
	if _, err := DNF4Previews().Upgrade(host); err != boom {
		t.Fatalf("host error = %v, want %v", err, boom)
	}
}

func TestDNFTransactionPreviews(t *testing.T) {
	const transaction = `Dependencies resolved.
Installing:
 tree             x86_64  1.8.0-10.el9  appstream  55 k
Installing dependencies:
 libfoo           noarch  1.0-1.el9     baseos     10 k
Removing:
 oldpkg           x86_64  1.0-1.el9     @baseos    10 k
Removing unused dependencies:
 oldlib           noarch  2.0-1.el9     @baseos     5 k
Transaction Summary
`
	var commands []string
	host := hostStub{runRootWithOutput: func(cmd string) (string, error) {
		commands = append(commands, cmd)
		return transaction, nil
	}}
	previews := DNF4Previews()

	installed, err := previews.Install(host, []string{"tree"})
	if err != nil || !slices.Equal(installed, []string{"tree", "libfoo"}) {
		t.Fatalf("install packages=%v error=%v", installed, err)
	}
	removed, err := previews.Autoremove(host)
	if err != nil || !slices.Equal(removed, []string{"oldpkg", "oldlib"}) {
		t.Fatalf("autoremove packages=%v error=%v", removed, err)
	}
	if _, err := previews.Purge(host, []string{"oldpkg"}); err != nil {
		t.Fatalf("purge preview: %v", err)
	}
	if _, err := previews.RollbackRemove(host, []string{"tree"}); err != nil {
		t.Fatalf("rollback removal preview: %v", err)
	}

	want := []string{
		`LC_ALL=C dnf --assumeno install 'tree'; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`,
		`LC_ALL=C dnf --assumeno autoremove; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`,
		`LC_ALL=C dnf --assumeno remove 'oldpkg'; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`,
		`LC_ALL=C dnf --assumeno --setopt=clean_requirements_on_remove=False remove 'tree'; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`,
	}
	if !slices.Equal(commands, want) {
		t.Fatalf("commands\n got: %q\nwant: %q", commands, want)
	}
}

func TestDNFTransactionProofAndErrors(t *testing.T) {
	dnf4 := DNF4Previews()
	dnf5 := DNF5Previews()

	for _, tc := range []struct {
		name     string
		previews Previews
		output   string
	}{
		{"dnf4 banner", dnf4, "Dependencies resolved.\n"},
		{"dnf5 banner", dnf5, "Transaction Summary\n"},
		{"explicit no-op", dnf4, "Nothing to do.\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := hostStub{runRootWithOutput: func(string) (string, error) { return tc.output, nil }}
			if _, err := tc.previews.Install(host, []string{"tree"}); err != nil {
				t.Fatalf("proof was rejected: %v", err)
			}
		})
	}

	host := hostStub{runRootWithOutput: func(string) (string, error) {
		return "localized heading\nsecond line\nthird line\nfourth line\n", nil
	}}
	_, err := dnf5.Purge(host, []string{"tree"})
	if err == nil || !strings.Contains(err.Error(), "dnf did not produce a transaction preview") ||
		strings.Contains(err.Error(), "fourth line") {
		t.Fatalf("unexpected bounded error: %v", err)
	}

	boom := errors.New("preview transport failed")
	bad := hostStub{runRootWithOutput: func(string) (string, error) { return "ignored", boom }}
	if _, err := dnf4.RollbackRemove(bad, []string{"tree"}); err != boom {
		t.Fatalf("host error = %v, want %v", err, boom)
	}
}
