# Packages Plugins

Installs, upgrades, and removes packages. There is one plugin per package
manager, and a step picks its package manager by naming the plugin:
`packages_apt`, `packages_dnf4`, or `packages_dnf5`.

Example:

```json
{
  "id": "packages-base",
  "plugin": "packages_apt",
  "config": {
    "update": "always",
    "upgrade": "once",
    "autoremove": "once",
    "install": ["nftables", "fail2ban"],
    "purge": ["telnet"],
    "purge_also_removes": ["telnet-common"]
  }
}
```

Config fields:

- `update`, `upgrade`, `autoremove`: `never`, `always`, `once`, `if_<N>[hdw]_since_last`, or omitted
- `install`: package names to install
- `purge`: package names to purge
- `purge_also_removes`: packages the profile permits the resolved purge
  transaction to remove as collateral

## Choosing the plugin

Hardline does not detect the package manager, and there is no `backend` config
key: the plugin name is the choice. A step naming a plugin that is not
registered is rejected at `verify-profile`, before hardline connects to a host.

That is not a limitation in practice, because a profile already pins one
`os.family` and `os.version`, so it was never free to change package manager at
runtime.

`packages_dnf4` and `packages_dnf5` are separate plugins because the two print
different transaction tables and dnf5 renamed `check-update` to `check-upgrade`.

| Plugin | Targets | Query | Install | Remove |
| --- | --- | --- | --- | --- |
| `packages_apt` | Debian, Ubuntu | `dpkg -s` | `apt-get install -y` | `apt-get purge -y` |
| `packages_dnf4` | RHEL 9, Rocky 9, Alma 9 | `rpm -q` | `dnf -y install` | `dnf -y remove` |
| `packages_dnf5` | Fedora 41+, RHEL 10 | `rpm -q` | `dnf -y install` | `dnf -y remove` |

The rpm query asks by name and then by provide (`rpm -q --whatprovides`). A dnf
package spec is not always an rpm name: dnf resolves it through `Provides` and
obsoletes too, so a name that no installed rpm carries can still be satisfied.
Recording such a request as absent would leave the journal wrong, rollback with
nothing to undo, and conflict detection reporting drift that is only the query
looking in the wrong place.

`purge` is not identical across them. On apt it is `apt-get purge`, which
removes configuration files too. On rpm there is no purge: `dnf remove` leaves
modified config files behind as `.rpmsave`. Hardline does not emulate the
difference.

## Operation Cadence

| Value | When the operation runs |
| --- | --- |
| omitted or `never` | never |
| `always` | on every apply |
| `once` | only when `install`/`purge` would actually change something on this host |
| `if_<N>[hdw]_since_last` | when at least `<N>` hours (`h`), days (`d`), or weeks (`w`) have passed since the last run, or when no run has been recorded |

`<N>` must be a positive integer and the unit must be one of `h`, `d`, `w`; anything else fails validation. The "last run" timestamps are per-operation marker files on the target: `/var/lib/hardline/last-update`, `last-upgrade`, and `last-autoremove`. Their mtime is what the comparison reads, so deleting one makes the next apply run that operation.

Rules:

- each plugin enforces its own package-name rule, rather than every target
  inheriting the union of all of them: `packages_apt` takes Debian policy names
  (`^[a-z0-9][a-z0-9+.-]{0,127}$`), the dnf plugins take rpm names, which are
  case-sensitive, may use underscores, and may be arch-qualified as `glibc.i686`
  (`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
- entries must not be empty, and a name cannot repeat within `install` or within `purge`
- the same package cannot appear in both `install` and `purge`
- `purge_also_removes` entries must be unique and cannot also appear in
  `install` or `purge`; they acknowledge collateral rather than request a second
  operation, and they have no effect without `purge`
- package operations are guarded by a lock check for that package manager (dpkg locks for apt, the rpm and dnf metadata locks otherwise), which fails fast rather than waiting
- every package command runs under a 30-minute per-command `timeout` on the target

## Plan previews

Plan reports what the transaction would do, reading it from the package manager
itself: `apt-get -s` for apt, `dnf check-update` / `check-upgrade` plus a
declined `--assumeno` transaction for the dnf plugins. `check-update` exits 100
when upgrades exist and `--assumeno` exits non-zero after declining; hardline
translates only those exit codes, so a genuine failure is reported as a failed
preview rather than as "nothing to do".

Every parsed command runs under `LC_ALL=C`. Both apt and dnf render their
banners and section headings through gettext, and a preview parsed from
translated output would silently find nothing to do while apply still ran the
transaction.

`dnf check-update` prints obsoletes in a trailing `Obsoleting Packages` section,
listing each replacement at column 0 with the package it replaces indented
beneath it. `dnf upgrade` installs those replacements, so plan counts them.

## Purge collateral

A purge is resolved after update, upgrade, and install, so its preview describes
the dependency graph the purge will actually run against. Apply compares that
preview with `purge` plus `purge_also_removes` and refuses the step if the
transaction reaches any further, naming what it would have taken. Declared
collateral is captured in the journal like an explicit purge, so rollback can
attempt to reinstall it too.

## Rollback

Rollback runs from the journal alone, with no profile in hand. The journalled
step type names the plugin that captured each record, which is what tells
rollback how to undo it.

Rollback of an install removes the package again. On the dnf plugins that
removal is previewed first and refused if the transaction reaches past the
package being undone: dnf resolves a removal outwards, so an unguarded undo
would also take whatever came to depend on the package after apply. The removal
itself runs with `clean_requirements_on_remove=False`, because undoing one
install must not also collect dependencies the run never installed.

Rollback of a purge reinstalls the package, preferring the exact version
captured before the purge and falling back to an unpinned install if that
fails. That pin is recorded in the capturing plugin's own syntax: `name=version`
for apt, and a full NEVRA (`name-[epoch:]version-release.arch`) for rpm, which
is the only ordering rpm resolves. `update`, `upgrade`, and `autoremove` are not
reversible; the journal records them with a best-effort note rather than undoing
them.

Plan rates the step's rollback fidelity from what it would really do: purging a
package that is installed is irreversible, because reinstalling it does not
bring back the configuration the purge deleted; installs, upgrades and
autoremoves are best-effort; a metadata refresh on its own reverts nothing and
leaves the verdict at deterministic.

The capture writes the same verdict into the journal, so the apply footer names
the irreversible steps plan warned about instead of downgrading them all to
best-effort. Only the declared `purge` list decides it: nothing in
`purge_also_removes` is passed to the purge command, so collateral goes when a
declared target goes and never on its own. The verdict does not change what
rollback attempts. An irreversible step is still walked object by object, and a
package it cannot reinstall is reported as degraded rather than aborting the
steps queued behind it.
