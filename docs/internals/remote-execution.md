# Remote Execution

Remote execution is funneled through `internals/remote.Client`.

## SSH Setup

`internals/connection.NewSSHClient` enforces:

- explicit `--user`
- explicit `--host`
- private-key authentication from `--keypath`
- host key verification through `known_hosts`
- immediate `sudo -n true` preflight, run before the client is handed back

Because the preflight lives inside `NewSSHClient`, every command that connects gets it, including `plan`. `apply` and `rollback` additionally call `EnsureNonInteractiveSudo` on their own after connecting.

Known-host lookup order is:

1. `Config.KnownHostsPath`
2. `HARDLINE_KNOWN_HOSTS`
3. `~/.ssh/known_hosts`

The SSH dial timeout is 10 seconds.

## Command Execution

- commands run over SSH sessions created from `golang.org/x/crypto/ssh`, one session per command
- root commands are wrapped as `sudo -n sh -lc '...'`
- root file writes use SFTP to a temp file and then `install -m ...` on the remote host
- the default per-command timeout is 5 minutes (`remote.DefaultCmdTimeout`). On expiry the SSH session is closed and the call returns `remote command timed out after <d>`
- apt operations opt out of that default via `RunRootWithTimeout`: a 30-minute shell-level `timeout` on the target, wrapped in a 35-minute SSH deadline so the shell timeout is the one that fires and returns a real error rather than a dropped session

The core methods are:

| Method | Root | Returns output |
| --- | --- | --- |
| `Run` | no | no |
| `RunWithOutput` | no | yes |
| `RunRoot` | yes | no |
| `RunRootWithOutput` | yes | yes |
| `RunRootWithTimeout` | yes | yes, with a caller-supplied deadline |
| `ReadRootFile` | yes | file contents, via `cat` |
| `WriteRootFile` | yes | no |
| `Stat` | no | `os.FileInfo`, over SFTP |

`pluginapi.Host` is the narrow interface plugins see: `RunRoot`, `RunRootWithOutput`, `RunRootWithTimeout`, `Stat`, `ReadRootFile`, and `WriteRootFile`. The non-root `Run` and `RunWithOutput` are not exposed to plugins.

## Root File Writes

`WriteRootFile`:

1. generates a random temp path `/tmp/.hardline-<hex>` from 8 bytes of `crypto/rand`
2. uploads the file over SFTP with mode `0600`, as the connecting user
3. runs `install -m <mode> -- <tmp> <dest> && rm -f -- <tmp>` as root, in one command

The temp file is only ever `0600` and the final mode is applied by `install`, so the content is never briefly readable at the destination mode. Both paths are shell-quoted. This keeps plugin code from having to manage upload mechanics directly.

## Remote OS Validation

`connection.CheckRemoteOS` reads `/etc/os-release` and compares:

- `ID` against the profile's `os.family`
- `VERSION_ID` against the profile's `os.version`

If the profile leaves `os.family` blank, the OS check is skipped. If it sets `family` but leaves `version` blank, only the family check runs.
