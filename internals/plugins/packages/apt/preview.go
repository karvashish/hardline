package apt

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

// simCmd is the simulate form behind every preview. LC_ALL=C pins the locale:
// the parser below matches apt's own "Inst"/"Remv" tokens, and apt renders
// those through gettext, so an unpinned command previews nothing on a
// localized host while apply still runs the transaction.
func simCmd(tail string) string {
	return "LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -s " + tail
}

func upgradePreview(host pluginapi.Host) ([]string, error) {
	out, err := host.RunRootWithOutput(simCmd("upgrade"))
	if err != nil {
		return nil, err
	}
	return parseSimulation(out, "Inst "), nil
}

func installPreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	out, err := host.RunRootWithOutput(packages.AppendPackages(simCmd("install"), pkgs))
	if err != nil {
		return nil, err
	}
	return parseSimulation(out, "Inst "), nil
}

func autoremovePreview(host pluginapi.Host) ([]string, error) {
	out, err := host.RunRootWithOutput(simCmd("autoremove"))
	if err != nil {
		return nil, err
	}
	return parseSimulation(out, "Remv ", "Purg "), nil
}

// purgePreview is the real purge transaction: apt resolves a purge outwards
// through reverse dependencies, so the set it prints is what apply will remove,
// not the set the profile named. Both tokens count - apt writes "Purg" for the
// packages whose configuration also goes and "Remv" for the rest.
func purgePreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	out, err := host.RunRootWithOutput(packages.AppendPackages(simCmd("purge"), pkgs))
	if err != nil {
		return nil, err
	}
	return parseSimulation(out, "Remv ", "Purg "), nil
}

// parseSimulation reads the "Inst <name> ..." / "Remv <name> ..." lines of an
// apt-get -s run, deduplicating while preserving apt's own ordering. A
// multiarch row names the package as "name:arch"; the architecture is dropped
// so the result compares against the names a profile writes.
func parseSimulation(out string, prefixes ...string) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !hasAnyPrefix(line, prefixes) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name, _, _ := strings.Cut(fields[1], ":")
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs
}

func hasAnyPrefix(line string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// dpkgMissMessage is what dpkg-query prints when it knows nothing about a
// package. It is the only output that means "absent"; see classifyDpkgProbe.
const dpkgMissMessage = "dpkg-query: no packages found matching"

// query reports whether name is installed, at which version, and the exact
// install argument that would restore it. apt pins with "name=version".
//
// stderr is folded into stdout because dpkg-query answers a miss there and
// exits 1, which is indistinguishable from a transport failure by exit code
// alone. Recording "was not installed" for a package that is installed writes a
// rollback snapshot that removes it.
func query(host pluginapi.Host, name string) (bool, string, string, error) {
	if host == nil {
		return false, "", "", fmt.Errorf("host context is required to query package %q", name)
	}
	cmd := `dpkg-query -W -f='HL:${Status}\t${Version}\n' ` + pluginapi.ShellArg(name) + ` 2>&1; echo "HL-RC:$?"`
	out, err := host.RunRootWithOutput(cmd)
	if err != nil {
		return false, "", "", fmt.Errorf("query package %q: %w", name, err)
	}
	return classifyDpkgProbe(name, out)
}

// dpkgAbsentStates are the states in which dpkg holds no files for a package.
// "config-files" is a purged-but-not-removed package: its files are gone, so
// the package is absent for the purposes of a snapshot, even though dpkg still
// has a record of it.
var dpkgAbsentStates = map[string]bool{
	"not-installed": true,
	"config-files":  true,
}

// classifyDpkgProbe turns the probe's output into an answer or an error. Only
// two readings are answers: dpkg reported a status it holds a definite opinion
// about, or dpkg reported that it has never heard of the package. A half-
// installed or half-configured package is neither, and an interrupted dpkg run
// is exactly how a host reaches those states, so they are propagated rather
// than rounded to "installed" or "absent".
func classifyDpkgProbe(name, out string) (bool, string, string, error) {
	codes := 0
	missed := false
	var noise []string
	var status, version string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if answer, ok := strings.CutPrefix(trimmed, "HL:"); ok {
			status, version, _ = strings.Cut(answer, "\t")
			continue
		}
		if _, ok := strings.CutPrefix(trimmed, "HL-RC:"); ok {
			codes++
			continue
		}
		if strings.HasPrefix(trimmed, dpkgMissMessage) {
			missed = true
			continue
		}
		noise = append(noise, trimmed)
	}
	if codes != 1 {
		return false, "", "", fmt.Errorf("query package %q: dpkg-query probe did not complete: %s", name, packages.FirstLines(out, 3))
	}
	if len(noise) > 0 {
		return false, "", "", fmt.Errorf("query package %q: dpkg-query reported %s", name, packages.FirstLines(strings.Join(noise, "\n"), 3))
	}
	if status == "" {
		if missed {
			return false, "", "", nil
		}
		return false, "", "", fmt.Errorf("query package %q: dpkg-query returned no status", name)
	}

	fields := strings.Fields(status)
	if len(fields) != 3 {
		return false, "", "", fmt.Errorf("query package %q: unexpected dpkg status %q", name, status)
	}
	if fields[1] != "ok" {
		return false, "", "", fmt.Errorf("query package %q: dpkg reports the package in error state %q", name, status)
	}
	switch {
	case fields[2] == "installed":
		// An installed package always has a version. Without one there is no pin
		// to journal, and rollback would reinstall whatever the repository offers
		// later rather than what was there before.
		if version == "" {
			return false, "", "", fmt.Errorf("query package %q: dpkg reports it installed with no version", name)
		}
		return true, version, name + "=" + version, nil
	case dpkgAbsentStates[fields[2]]:
		return false, "", "", nil
	default:
		return false, "", "", fmt.Errorf(
			"query package %q: dpkg reports the package neither installed nor absent (%q); resolve it with dpkg --configure -a", name, status)
	}
}
