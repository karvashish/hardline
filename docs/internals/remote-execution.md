# Remote Execution

Remote execution is funneled through `internals/remote.Client`.

## SSH Setup

`internals/connection.NewSSHClient` enforces:

- explicit `--user`
- explicit `--host`
- private-key authentication from `--keypath`
- host key verification through `known_hosts`
- immediate `sudo -n true` preflight

Known-host lookup order is:

1. `Config.KnownHostsPath`
2. `HARDLINE_KNOWN_HOSTS`
3. `~/.ssh/known_hosts`

The SSH dial timeout is 10 seconds.

## Command Execution

- commands run over SSH sessions created from `golang.org/x/crypto/ssh`
- root commands are wrapped as `sudo -n sh -lc '...'`
- root file writes use SFTP to a temp file and then `install -m ...` on the remote host
- the default per-command timeout is 5 minutes
- apt operations use a longer outer timeout

The core methods are:

- `Run`
- `RunRoot`
- `RunWithOutput`
- `RunRootWithOutput`
- `RunRootWithTimeout`

## Root File Writes

`WriteRootFile` is a two-stage operation:

1. generate a random temp path like `/tmp/.hardline-<hex>`
2. upload the file over SFTP with mode `0600`
3. install it into place with `install -m <mode>`
4. remove the temp file

This keeps plugin code from having to manage upload mechanics directly.

## Remote OS Validation

`connection.CheckRemoteOS` reads `/etc/os-release` and compares:

- `ID` against the profile's `os.family`
- `VERSION_ID` against the profile's `os.version`

If the profile leaves `os.family` blank, the OS check is skipped. If it sets `family` but leaves `version` blank, only the family check runs.
