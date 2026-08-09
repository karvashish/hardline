package apt

import (
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
	return parseSimulation(out, "Remv "), nil
}

// parseSimulation reads the "Inst <name> ..." / "Remv <name> ..." lines of an
// apt-get -s run, deduplicating while preserving apt's own ordering.
func parseSimulation(out, prefix string) []string {
	var pkgs []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := fields[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		pkgs = append(pkgs, name)
	}
	return pkgs
}

// query reports whether name is installed, at which version, and the exact
// install argument that would restore it. apt pins with "name=version".
func query(host pluginapi.Host, name string) (bool, string, string, error) {
	cmd := "dpkg-query -W -f='${Status}\\t${Version}' " + pluginapi.ShellArg(name) + " 2>/dev/null || true"
	out, err := host.RunRootWithOutput(cmd)
	if err != nil {
		return false, "", "", err
	}
	raw := strings.TrimSpace(out)
	if raw == "install ok installed" {
		return true, "", "", nil
	}
	if version, ok := strings.CutPrefix(raw, "install ok installed\t"); ok {
		return true, version, name + "=" + version, nil
	}
	return false, "", "", nil
}
