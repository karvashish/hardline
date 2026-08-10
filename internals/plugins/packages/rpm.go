package packages

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

// rpm queries are identical under both dnf generations, so they sit here rather
// than in dnf4/ with dnf5/ reaching into it. Anything that reads dnf's own
// output stays in the subpackage, because the two print different tables.

// RPMNameRe accepts an rpm name, optionally arch-qualified as a profile may
// write it ("glibc.i686"). Wider than the Debian rule: rpm names are
// case-sensitive and use underscores.
var RPMNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// RPMPinRe accepts a full NEVRA, "name-[epoch:]version-release.arch". The
// architecture comes last, which is the ordering rpm resolves. "name.arch-EVR"
// is not a valid spec, and is what concatenating a profile's arch-qualified
// name with a version used to produce.
var RPMPinRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}-[0-9][A-Za-z0-9._+:~^-]{0,127}\.[a-z0-9_]{1,16}$`)

// rpmQueryFmt prefixes the answer with a marker: rpm prints "package X is not
// installed" on stdout when the query misses, and the marker is what separates
// that message from a real answer. Two tab-separated fields follow: the EVR,
// which is what plan and conflict detection compare, and the NEVRA, which is
// the only form that pins an exact restore.
const rpmQueryFmt = `--qf 'HL:%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}-%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}.%{ARCH}\n' `

const (
	rpmQueryCmd    = `rpm -q ` + rpmQueryFmt
	rpmProvidesCmd = `rpm -q --whatprovides ` + rpmQueryFmt
)

// Both queries run unconditionally and both statuses are reported, because the
// only safe reading of "absent" is that rpm said so twice, in its own words.
// Redirecting stderr into stdout is what makes those words available: a probe
// that only sees an exit code cannot tell a missing package from a broken
// rpmdb, and both exit 1.
const rpmProbeRC = "HL-RC:"

func rpmProbe(arg string) string {
	return rpmQueryCmd + arg + ` 2>&1; echo "` + rpmProbeRC + `$?"; ` +
		rpmProvidesCmd + arg + ` 2>&1; echo "` + rpmProbeRC + `$?"`
}

// RPMQuery reports whether name is installed, at which version, and the exact
// install argument that would restore that version.
//
// A dnf package spec is not always an rpm name: dnf resolves it through
// Provides and obsoletes too, so a name that misses is asked again as a
// provide. Journalling "absent" for a request dnf did install would leave
// rollback with nothing to undo and conflict detection reading drift that is
// only the query looking in the wrong place.
func RPMQuery(host pluginapi.Host, name string) (installed bool, version, pin string, err error) {
	if host == nil {
		return false, "", "", fmt.Errorf("host context is required to query package %q", name)
	}
	out, err := host.RunRootWithOutput(rpmProbe(pluginapi.ShellArg(name)))
	if err != nil {
		return false, "", "", fmt.Errorf("query package %q: %w", name, err)
	}
	return classifyRPMProbe(name, out)
}

// classifyRPMProbe turns the probe's output into an answer or an error. Absent
// is the narrowest of the three readings: rpm has to have printed its own miss
// message for both queries and nothing else. Any other output - a corrupt
// rpmdb, a truncated session, a sudo refusal - is propagated, because recording
// "was not installed" for a package that is installed writes a rollback
// snapshot that uninstalls it.
func classifyRPMProbe(name, out string) (bool, string, string, error) {
	codes := 0
	var noise []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if answer, ok := strings.CutPrefix(trimmed, "HL:"); ok {
			// Both fields are required. Without the NEVRA there is no pin to
			// journal, and rollback would reinstall whatever the repository
			// offers later rather than what was there before.
			evr, nevra, found := strings.Cut(answer, "\t")
			if !found || evr == "" || nevra == "" {
				return false, "", "", fmt.Errorf("query package %q: malformed rpm answer %q", name, answer)
			}
			return true, evr, nevra, nil
		}
		if _, ok := strings.CutPrefix(trimmed, rpmProbeRC); ok {
			codes++
			continue
		}
		if isRPMMissMessage(trimmed) {
			continue
		}
		noise = append(noise, trimmed)
	}
	if codes != 2 {
		return false, "", "", fmt.Errorf("query package %q: rpm probe did not complete: %s", name, FirstLines(out, 3))
	}
	if len(noise) > 0 {
		return false, "", "", fmt.Errorf("query package %q: rpm reported %s", name, FirstLines(strings.Join(noise, "\n"), 3))
	}
	return false, "", "", nil
}

// isRPMMissMessage matches the two sentences rpm prints when a query finds
// nothing. They are the only outputs that mean "not installed".
func isRPMMissMessage(line string) bool {
	if strings.HasPrefix(line, "package ") && strings.HasSuffix(line, " is not installed") {
		return true
	}
	return strings.HasPrefix(line, "no package provides ")
}

// UnexpectedRemovals reports which packages of a previewed removal transaction
// nobody asked for. A rollback asks for one package - the install this run made
// - and a purge asks for the names the step declares plus whatever collateral
// it declares it accepts. Anything else in that table is a package the host
// gained a use for independently, and removing it is collateral damage rather
// than the operation the profile described.
func UnexpectedRemovals(want []string, preview []string) []string {
	allowed := make(map[string]struct{}, len(want))
	for _, name := range want {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if trimmed, ok := TrimRPMArch(name); ok {
			name = trimmed
		}
		allowed[name] = struct{}{}
	}
	var extra []string
	for _, pkg := range preview {
		if _, ok := allowed[pkg]; !ok {
			extra = append(extra, pkg)
		}
	}
	return extra
}

var rpmArches = []string{
	"x86_64", "noarch", "aarch64", "i686", "i386",
	"armv7hl", "ppc64le", "s390x", "src",
}

// TrimRPMArch turns "bash.x86_64" into "bash". A token without a known arch
// suffix is not a package column, so the caller skips the line: that is what
// keeps stray banner text out of the parsed package list.
func TrimRPMArch(token string) (string, bool) {
	for _, arch := range rpmArches {
		if name, ok := strings.CutSuffix(token, "."+arch); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

// IsRPMArch identifies the arch column of a transaction table, where the arch
// is a field of its own rather than a suffix.
func IsRPMArch(token string) bool {
	for _, arch := range rpmArches {
		if token == arch {
			return true
		}
	}
	return false
}

// ParseRPMTransaction reads the transaction table dnf prints before asking for
// confirmation. Section headers sit at column 0 and package rows are indented,
// so the current section decides whether a row counts. Both dnf generations
// lay the table out this way; they differ only in the banner that proves a
// preview was produced, which the caller checks.
func ParseRPMTransaction(out string, wanted map[string]bool) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	section := ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			section = ""
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = ""
			if strings.HasSuffix(trimmed, ":") {
				section = trimmed
			}
			continue
		}
		if !wanted[section] {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || !IsRPMArch(fields[1]) {
			continue
		}
		name := fields[0]
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs
}
