package dnf4

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

// dnf check-update exits 100 when updates are available, which is a result and
// not a failure. Translating only that code keeps a genuine failure an error
// instead of an empty upgrade list.
const checkUpdateCmd = lc + `dnf -q check-update; rc=$?; [ "$rc" = 100 ] && exit 0; exit $rc`

// A declined transaction exits 1. Same reasoning as above: translate that one
// code, and let the output check below catch a failure that shares it.
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
	out, err := host.RunRootWithOutput(checkUpdateCmd)
	if err != nil {
		return nil, err
	}
	return parseCheckUpdate(out), nil
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

// parseCheckUpdate reads the "<name>.<arch>  <evr>  <repo>" lines of
// dnf check-update. The trailing "Obsoleting Packages" section lists each
// replacement at column 0 with the package it replaces indented beneath it.
// dnf upgrade installs those replacements, so the replacement rows are real
// changes and the indented rows are not.
func parseCheckUpdate(out string) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	obsoleting := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Obsoleting Packages") {
			obsoleting = true
			continue
		}
		if obsoleting && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			continue
		}
		fields := strings.Fields(trimmed)
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

// parseTransaction reads the transaction table dnf4 prints before asking for
// confirmation. The "Dependencies resolved" banner is what proves a preview was
// actually produced; dnf5 closes with a different one.
func parseTransaction(out string, wanted map[string]bool) ([]string, error) {
	if !strings.Contains(out, "Dependencies resolved") && !strings.Contains(out, "Nothing to do") {
		return nil, fmt.Errorf("dnf did not produce a transaction preview: %s", packages.FirstLines(out, 3))
	}
	return packages.ParseRPMTransaction(out, wanted), nil
}
