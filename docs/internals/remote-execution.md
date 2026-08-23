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
- package-manager operations opt out of that default via `RunRootWithTimeout`: a 30-minute shell-level `timeout` on the target, wrapped in a 35-minute SSH deadline so the shell timeout is the one that fires and returns a real error rather than a dropped session

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

- `ID` against the profile's `os.family`, case-insensitively and exactly
- `VERSION_ID` against the profile's `os.version`
- `VARIANT_ID` against the profile's `os.variant`

Values are read with their surrounding quotes stripped, since `/etc/os-release` permits both `ID=ubuntu` and `ID='ubuntu'`.

Signed profiles must provide a non-empty `os.family` and a numeric, dot-separated `os.version`; schema validation rejects a profile before connection otherwise. Version matching uses the components the profile declares: `9` accepts `9` and any `9.x` value, while `24.04` accepts `24.04` and any `24.04.x` value but rejects `24.10`. The variant check is case-insensitive and only refuses a host that publishes a *different* `VARIANT_ID`; a host that publishes none (the RHEL family, Ubuntu) cannot contradict the profile and is not refused on a guess. The empty-value guards in `CheckRemoteOS` remain only for callers that construct profile data directly in Go.
