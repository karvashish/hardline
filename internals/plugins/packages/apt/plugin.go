// Package apt is the packages_apt plugin: package management on Debian-family
// hosts through apt-get and dpkg.
package apt

import (
	"regexp"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const pluginName = "packages_apt"

// Debian policy: a package name is lower case letters, digits, plus, minus and
// period, starting alphanumeric. This is intentionally narrower than rpm.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)

// An exact-version install argument, "name=version". Debian versions add colon
// for the epoch and tilde for pre-releases.
var pinRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}=[A-Za-z0-9.+:~-]{1,128}$`)

const lockHint = "investigate with: sudo lsof /var/lib/dpkg/lock"

var lockCheck = packages.LockProbe(
	"/var/lib/dpkg/lock",
	"/var/lib/apt/lists/lock",
	"/var/lib/dpkg/lock-frontend",
)

// DEBIAN_FRONTEND has to precede timeout(1) so the setting reaches apt-get;
// timeout itself will not accept a VAR=value operand.
func cmd(tail string) string {
	return "DEBIAN_FRONTEND=noninteractive " + packages.TimeoutCmd(tail)
}

var (
	updateCmd     = cmd("apt-get update -y")
	upgradeCmd    = cmd("apt-get upgrade -y")
	installCmd    = cmd("apt-get install -y")
	purgeCmd      = cmd("apt-get purge -y")
	autoremoveCmd = cmd("apt-get autoremove -y")
)

func backend() packages.Backend {
	return packages.Backend{
		Name:        pluginName,
		NamePattern: nameRe,
		PinPattern:  pinRe,
		CheckLock: func(host pluginapi.Host) error {
			return packages.CheckLock(host, lockCheck, lockHint)
		},
		Query: query,
		Commands: packages.Commands{
			Update:     updateCmd,
			Upgrade:    upgradeCmd,
			Install:    installCmd,
			Purge:      purgeCmd,
			Autoremove: autoremoveCmd,
		},
		Previews: packages.Previews{
			Upgrade:    upgradePreview,
			Install:    installPreview,
			Purge:      purgePreview,
			Autoremove: autoremovePreview,
		},
	}
}

func Plugin() pluginapi.Plugin { return backend().Plugin() }
