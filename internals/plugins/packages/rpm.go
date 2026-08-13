package packages

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/karvashish/hardline/pkg/pluginapi"
)

var RPMNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)

var RPMPinRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}-[0-9][A-Za-z0-9._+:~^-]{0,127}\.[a-z0-9_]{1,16}$`)

const rpmQueryFmt = `--qf 'HL:%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}-%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}.%{ARCH}\n' `

const (
	rpmQueryCmd    = `rpm -q ` + rpmQueryFmt
	rpmProvidesCmd = `rpm -q --whatprovides ` + rpmQueryFmt
)

const rpmProbeRC = "HL-RC:"

func rpmProbe(arg string) string {
	return rpmQueryCmd + arg + ` 2>&1; echo "` + rpmProbeRC + `$?"; ` +
		rpmProvidesCmd + arg + ` 2>&1; echo "` + rpmProbeRC + `$?"`
}

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

func classifyRPMProbe(name, out string) (bool, string, string, error) {
	codes := 0
	var noise []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if answer, ok := strings.CutPrefix(trimmed, "HL:"); ok {
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

func isRPMMissMessage(line string) bool {
	if strings.HasPrefix(line, "package ") && strings.HasSuffix(line, " is not installed") {
		return true
	}
	return strings.HasPrefix(line, "no package provides ")
}

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

func TrimRPMArch(token string) (string, bool) {
	for _, arch := range rpmArches {
		if name, ok := strings.CutSuffix(token, "."+arch); ok && name != "" {
			return name, true
		}
	}
	return "", false
}

func IsRPMArch(token string) bool {
	for _, arch := range rpmArches {
		if token == arch {
			return true
		}
	}
	return false
}

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
