package packages

import (
	"regexp"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

// rpm queries are identical under both dnf generations, so they sit here rather
// than in dnf4/ with dnf5/ reaching into it. Anything that reads dnf's own
// output stays in the subpackage, because the two print different tables.

const RPMInstalledFmt = "rpm -q %s >/dev/null 2>&1"

// RPMNameRe accepts an rpm name, optionally arch-qualified as a profile may
// write it ("glibc.i686"). Wider than the Debian rule: rpm names are
// case-sensitive and use underscores.
var RPMNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

// RPMPinRe accepts a full NEVRA, "name-[epoch:]version-release.arch". The
// architecture comes last, which is the ordering rpm resolves. "name.arch-EVR"
// is not a valid spec, and is what concatenating a profile's arch-qualified
// name with a version used to produce.
var RPMPinRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}-[0-9][A-Za-z0-9._+:~^-]{0,127}\.[a-z0-9_]{1,16}$`)

// rpmQueryCmd prefixes the answer with a marker: rpm prints "package X is not
// installed" on stdout when the query misses, and the marker is what separates
// that message from a real answer. Two tab-separated fields follow: the EVR,
// which is what plan and conflict detection compare, and the NEVRA, which is
// the only form that pins an exact restore.
const rpmQueryCmd = `rpm -q --qf 'HL:%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}-%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}.%{ARCH}\n' `

// RPMQuery reports whether name is installed, at which version, and the exact
// install argument that would restore that version.
func RPMQuery(host pluginapi.Host, name string) (installed bool, version, pin string, err error) {
	out, err := host.RunRootWithOutput(rpmQueryCmd + pluginapi.ShellArg(name) + " 2>/dev/null || true")
	if err != nil {
		return false, "", "", err
	}
	for _, line := range strings.Split(out, "\n") {
		answer, ok := strings.CutPrefix(strings.TrimSpace(line), "HL:")
		if !ok {
			continue
		}
		evr, nevra, found := strings.Cut(answer, "\t")
		if !found {
			return true, answer, "", nil
		}
		return true, evr, nevra, nil
	}
	return false, "", "", nil
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
