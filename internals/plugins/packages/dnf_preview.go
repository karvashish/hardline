package packages

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

const (
	dnfLocalePrefix = "LC_ALL=C "
	dnfAssumeNo     = dnfLocalePrefix + `dnf --assumeno `
	dnfAssumeNoTail = `; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`
	dnfRemoveOpts   = "--setopt=clean_requirements_on_remove=False "
)

var dnfInstallSections = map[string]bool{
	"Installing:":                   true,
	"Installing dependencies:":      true,
	"Installing weak dependencies:": true,
	"Upgrading:":                    true,
	"Reinstalling:":                 true,
}

var dnfRemoveSections = map[string]bool{
	"Removing:":                     true,
	"Removing unused dependencies:": true,
	"Removing dependent packages:":  true,
}

// DNFCommands returns the apply and rollback commands shared by dnf4 and
// dnf5. Rollback disables dependency cleanup; an ordinary purge must leave it
// enabled so its preview exposes every collateral removal.
func DNFCommands() Commands {
	return Commands{
		Update:         TimeoutCmd("dnf -q -y makecache --refresh"),
		Upgrade:        TimeoutCmd("dnf -y upgrade"),
		Install:        TimeoutCmd("dnf -y install"),
		Purge:          TimeoutCmd("dnf -y remove"),
		Autoremove:     TimeoutCmd("dnf -y autoremove"),
		RollbackRemove: TimeoutCmd("dnf -y " + dnfRemoveOpts + "remove"),
	}
}

// dnfPreviews is a configured DNF preview implementation. The generations
// share commands and transaction tables but differ in their upgrade verb and
// in the banner that proves a transaction preview completed.
type dnfPreviews struct {
	checkCommand      string
	transactionBanner string
	skipObsoletedRows bool
}

// DNF4Previews configures dnf4's check-update listing and completion proof.
func DNF4Previews() Previews {
	p := dnfPreviews{
		checkCommand: dnfLocalePrefix +
			`dnf -q check-update; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`,
		transactionBanner: "Dependencies resolved",
		skipObsoletedRows: true,
	}
	return p.backendPreviews()
}

// DNF5Previews configures dnf5's check-upgrade listing and completion proof.
func DNF5Previews() Previews {
	p := dnfPreviews{
		checkCommand: dnfLocalePrefix +
			`dnf -q check-upgrade; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`,
		transactionBanner: "Transaction Summary",
	}
	return p.backendPreviews()
}

func (p dnfPreviews) backendPreviews() Previews {
	return Previews{
		Upgrade:        p.upgrade,
		Install:        p.install,
		Purge:          p.purge,
		Autoremove:     p.autoremove,
		RollbackRemove: p.remove,
	}
}

// upgrade previews all available upgrades. Exit 100 is translated by the
// command because DNF uses it to mean "updates available", not failure.
func (p dnfPreviews) upgrade(host pluginapi.Host) ([]string, error) {
	out, err := host.RunRootWithOutput(p.checkCommand)
	if err != nil {
		return nil, err
	}
	return parseDNFUpgradeList(out, p.skipObsoletedRows), nil
}

func (p dnfPreviews) install(host pluginapi.Host, names []string) ([]string, error) {
	return p.runTransaction(host, AppendPackages(dnfAssumeNo+"install", names)+dnfAssumeNoTail, dnfInstallSections)
}

func (p dnfPreviews) autoremove(host pluginapi.Host) ([]string, error) {
	return p.runTransaction(host, dnfAssumeNo+"autoremove"+dnfAssumeNoTail, dnfRemoveSections)
}

// purge previews the real removal with dependency cleanup left at its default.
func (p dnfPreviews) purge(host pluginapi.Host, names []string) ([]string, error) {
	return p.runTransaction(host, AppendPackages(dnfAssumeNo+"remove", names)+dnfAssumeNoTail, dnfRemoveSections)
}

// remove previews rollback with dependency cleanup disabled.
func (p dnfPreviews) remove(host pluginapi.Host, names []string) ([]string, error) {
	cmd := AppendPackages(dnfAssumeNo+dnfRemoveOpts+"remove", names) + dnfAssumeNoTail
	return p.runTransaction(host, cmd, dnfRemoveSections)
}

func (p dnfPreviews) runTransaction(host pluginapi.Host, command string, wanted map[string]bool) ([]string, error) {
	out, err := host.RunRootWithOutput(command)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(out, p.transactionBanner) && !strings.Contains(out, "Nothing to do") {
		return nil, fmt.Errorf("dnf did not produce a transaction preview: %s", FirstLines(out, 3))
	}
	return ParseRPMTransaction(out, wanted), nil
}

func parseDNFUpgradeList(out string, skipObsoletedRows bool) []string {
	var packages []string
	seen := make(map[string]struct{})
	obsoleting := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Obsoleting Packages") {
			obsoleting = true
			continue
		}
		if skipObsoletedRows && obsoleting && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		name, ok := TrimRPMArch(fields[0])
		if !ok {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		packages = append(packages, name)
	}
	return packages
}
