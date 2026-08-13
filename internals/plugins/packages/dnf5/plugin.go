package dnf5

import (
	"github.com/karvashish/hardline/internals/plugins/packages"
	"github.com/karvashish/hardline/pkg/pluginapi"
)

const pluginName = "packages_dnf5"

const lockHint = "investigate with: sudo lsof /var/lib/rpm/.rpm.lock"

var lockCheck = packages.LockProbe(
	"/var/lib/rpm/.rpm.lock",
	"/var/cache/libdnf5/*.pid",
)

func backend() packages.Backend {
	return packages.Backend{
		Name:        pluginName,
		NamePattern: packages.RPMNameRe,
		PinPattern:  packages.RPMPinRe,
		CheckLock: func(host pluginapi.Host) error {
			return packages.CheckLock(host, lockCheck, lockHint)
		},
		Query:    packages.RPMQuery,
		Commands: packages.DNFCommands(),
		Previews: packages.DNF5Previews(),
	}
}

func Plugin() pluginapi.Plugin { return backend().Plugin() }
