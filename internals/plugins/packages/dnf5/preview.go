package dnf5

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

// Every parsed dnf command is pinned to LC_ALL=C. The parsers here match dnf's
// own banners and section headings, and dnf renders those through gettext: on
// a localized host an unpinned command previews nothing while apply still runs
// the transaction.
const lc = "LC_ALL=C "

// Exit 100 means upgrades are available; anything else stays a failure.
const checkUpgradeCmd = lc + `dnf -q check-upgrade; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`

// A declined transaction exits 1. Translate that one code, and let the output
// check below catch a failure that shares it.
const (
	assumeNo     = lc + `dnf --assumeno `
	assumeNoTail = `; rc=$?; [ "$rc" = 1 ] && exit 0; exit $rc`
)

var installSections = map[string]bool{
	"Installing:":                   true,
	"Installing dependencies:":      true,
	"Installing weak dependencies:": true,
	"Upgrading:":                    true,
	"Reinstalling:":                 true,
}

var removeSections = map[string]bool{
	"Removing:":                     true,
	"Removing unused dependencies:": true,
	"Removing dependent packages:":  true,
}

func upgradePreview(host pluginapi.Host) ([]string, error) {
	out, err := host.RunRootWithOutput(checkUpgradeCmd)
	if err != nil {
		return nil, err
	}
	return parseCheckUpgrade(out), nil
}

func installPreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	out, err := host.RunRootWithOutput(packages.AppendPackages(assumeNo+"install", pkgs) + assumeNoTail)
	if err != nil {
		return nil, err
	}
	return parseTransaction(out, installSections)
}

func autoremovePreview(host pluginapi.Host) ([]string, error) {
	out, err := host.RunRootWithOutput(assumeNo + "autoremove" + assumeNoTail)
	if err != nil {
		return nil, err
	}
	return parseTransaction(out, removeSections)
}

// removeOpts turns off the dependency cleanup dnf does by default. It belongs
// on a rollback removal only: undoing an install must not also collect
// dependencies this run never installed.
const removeOpts = "--setopt=clean_requirements_on_remove=False "

// removePreview lists everything a removal would actually take, so rollback can
// refuse one that reaches past the package it is undoing.
func removePreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	out, err := host.RunRootWithOutput(packages.AppendPackages(assumeNo+removeOpts+"remove", pkgs) + assumeNoTail)
	if err != nil {
		return nil, err
	}
	return parseTransaction(out, removeSections)
}

// parseCheckUpgrade reads the "<name>.<arch> <evr> <repo>" lines of
// dnf check-upgrade. dnf5 prints obsoletes in the same flat listing, so unlike
// dnf4 there is no trailing section to treat separately.
func parseCheckUpgrade(out string) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		name, ok := packages.TrimRPMArch(fields[0])
		if !ok {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs
}

// parseTransaction reads the transaction table dnf5 prints before asking for
// confirmation. dnf5 closes with a "Transaction Summary" block instead of
// dnf4's "Dependencies resolved" banner, so that is what proves a preview was
// actually produced.
func parseTransaction(out string, wanted map[string]bool) ([]string, error) {
	if !strings.Contains(out, "Transaction Summary") && !strings.Contains(out, "Nothing to do") {
		return nil, fmt.Errorf("dnf did not produce a transaction preview: %s", packages.FirstLines(out, 3))
	}
	return packages.ParseRPMTransaction(out, wanted), nil
}
