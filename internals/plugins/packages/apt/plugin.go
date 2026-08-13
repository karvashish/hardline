package apt

import (
	"regexp"

	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const pluginName = "packages_apt"

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}$`)

var pinRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{0,127}=[A-Za-z0-9.+:~-]{1,128}$`)

const lockHint = "investigate with: sudo lsof /var/lib/dpkg/lock"

var lockCheck = packages.LockProbe(
	"/var/lib/dpkg/lock",
	"/var/lib/apt/lists/lock",
	"/var/lib/dpkg/lock-frontend",
)

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
