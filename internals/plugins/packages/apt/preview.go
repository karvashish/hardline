package apt

import (
	"fmt"
	"strings"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

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

func purgePreview(host pluginapi.Host, pkgs []string) ([]string, error) {
	out, err := host.RunRootWithOutput(packages.AppendPackages(simCmd("purge"), pkgs))
	if err != nil {
		return nil, err
	}
	return parseSimulation(out, "Remv ", "Purg "), nil
}

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

const dpkgMissMessage = "dpkg-query: no packages found matching"

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

var dpkgAbsentStates = map[string]bool{
	"not-installed": true,
	"config-files":  true,
}

func classifyDpkgProbe(name, out string) (bool, string, string, error) {
	codes := 0
	missed := false
	answers := 0
	var noise []string
	var status, version string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if answer, ok := strings.CutPrefix(trimmed, "HL:"); ok {
			answers++
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
		return false, "", "", fmt.Errorf("query package %q: dpkg-query probe did not complete: %s", name, pluginapi.FirstLines(out, 3))
	}
	if len(noise) > 0 {
		return false, "", "", fmt.Errorf("query package %q: dpkg-query reported %s", name, pluginapi.FirstLines(strings.Join(noise, "\n"), 3))
	}
	// A multiarch name answers once per architecture, and letting the last row win would pin and
	// install whichever one dpkg printed second.
	if answers > 1 {
		return false, "", "", fmt.Errorf(
			"query package %q: dpkg-query answers for %d architectures; name the architecture, as in %q",
			name, answers, name+":amd64")
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
