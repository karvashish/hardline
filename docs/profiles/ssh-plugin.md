# SSH Plugin

Writes the sshd policy drop-in, proves it parses, activates it, and then reads
the effective configuration back out of sshd.

```json
{
  "id": "ssh-policy",
  "plugin": "ssh",
  "config": {
    "path": "/etc/ssh/sshd_config.d/00-hardline-ssh.conf",
    "mode": "0600",
    "service": "sshd",
    "settings": {
      "PasswordAuthentication": "no",
      "PermitRootLogin": "no",
      "KbdInteractiveAuthentication": "no",
      "MaxAuthTries": 4,
      "LogLevel": "VERBOSE"
    },
    "verify_contexts": [
      { "user": "deploy", "host": "build.example", "addr": "10.0.0.5" }
    ]
  }
}
```

Config fields:

- `path`: **required**. Managed path under `/etc/ssh/sshd_config.d/`, which is what sshd includes. sshd keeps the **first** value it obtains for most keywords and reads its includes in lexical order, so the file must sort before any vendor or cloud-init drop-in. Use the `00-hardline` prefix here. The managed-path rule accepts `00-hardline*` and `99-hardline*` on any path and cannot tell the two apart by directory, so a `99-` name under `sshd_config.d` passes validation and is then shadowed by whatever sorts ahead of it
- `mode`: **required**. Octal
- `service`: **required**. `ssh` on Debian and Ubuntu, `sshd` on the RHEL family. The profile states it; the engine carries no distribution knowledge
- `settings`: **required**. Keyword to value, at least one. Values are strings or integers
- `verify_contexts`: optional. Connections to re-check the effective policy under. `user`, `host` and `addr` are all required per entry, because sshd needs all three to evaluate `Match`

## Why this is not a template plus a service step

Writing the file is the easy half, and on its own it proves nothing:

- Nothing runs `sshd -t`, so a bad directive lands on disk. The reload then
  fails, or the next boot leaves sshd refusing to start.
- Nothing runs `sshd -T`, so nothing checks the policy the daemon is actually
  running. A directive earlier in the main config silently shadows the drop-in,
  and a keyword this sshd no longer implements is dropped without an error.
- Nothing evaluates `Match`. A `Match` block elsewhere can re-enable for some
  users what the drop-in denied for everyone, and the run still reports aligned.
- Nothing guards management access. `PermitRootLogin no`, an `AllowUsers` list
  or a `DenyGroups` entry can cut the connection the run is using, and a run
  cannot undo what it can no longer reach.

## What it does

Apply runs in this order:

1. Renders the drop-in and stages it beside the destination under a name the
   `*.conf` include glob does not match.
2. Runs `sshd -t -f` on the staged file alone. A syntax error in content this
   profile wrote is caught with the host still untouched.
3. Installs the candidate over the destination.
4. Runs `sshd -t` on the whole configuration. This is what catches a keyword
   that is legal by itself and conflicts with what the host already declares.
5. Runs `sshd -T`. Because sshd reads its configuration from disk rather than
   from the running daemon, this returns the policy the reload is *about to*
   activate, which makes the next step a preflight rather than a post-mortem.
6. Refuses the activation if that prospective policy would lock this run out.
7. Reloads the unit.
8. Runs `sshd -T` again, globally and once per `verify_contexts` entry, and
   fails the step unless every declared keyword is reported with the declared
   value.

Any failure from step 4 onward restores the previous drop-in, so a refusal never
leaves the host carrying a configuration the next reboot would apply. A failure
at step 7 or 8, once the daemon has already been reloaded, also reloads it back
off the restored file: putting the bytes back is not enough on its own, because
sshd would keep running the policy that was just refused. A reload that reports
an error counts as having happened, since it may have taken effect anyway.

A host whose file already matches **and** whose effective policy already carries
every declared keyword gets no write and no reload. The file matching on its own
is not enough: a drop-in on disk that the daemon has never read is the exact
failure this plugin exists to prevent.

## The key-authentication guard

The guard reads the prospective effective configuration, so it accounts for what
the host already declares and not only what this profile asked for. It refuses
one thing: a policy that sets `PubkeyAuthentication` to anything but `yes`.
hardline reaches the host over an SSH key, so that policy ends the run's own
connection before it can report what it did.

Which accounts and groups may log in is policy, not a lockout hardline rules on.
`PermitRootLogin`, `AllowUsers`, `AllowGroups`, `DenyUsers` and `DenyGroups` are
applied as written. Answering them would mean inferring which identity this run
is connected as, and a wrong inference either invents access the host does not
grant or refuses a policy that is fine.

## Accepted keywords

The keyword set is a whitelist. A keyword outside it is rejected at
`verify-profile`, offline, before any connection is made — a keyword this plugin
cannot verify took effect is one whose hardening claim nothing checks.

`AllowAgentForwarding`, `AllowTcpForwarding`, `ClientAliveCountMax`,
`ClientAliveInterval`, `Compression`, `GatewayPorts`, `HostbasedAuthentication`,
`IgnoreRhosts`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `LogLevel`,
`MaxAuthTries`, `MaxSessions`, `PasswordAuthentication`, `PermitEmptyPasswords`,
`PermitRootLogin`, `PermitTunnel`, `PermitUserEnvironment`, `PrintLastLog`,
`PubkeyAuthentication`, `StrictModes`, `TCPKeepAlive`, `UsePAM`,
`X11Forwarding`.

Two spellings of one keyword in the same step are rejected: both would render
and sshd would keep whichever sorted first, while the profile claims both.

Values are checked per keyword, not only by type:

| Keyword | Accepted values |
| --- | --- |
| `AllowAgentForwarding`, `HostbasedAuthentication`, `IgnoreRhosts`, `KbdInteractiveAuthentication`, `PasswordAuthentication`, `PermitEmptyPasswords`, `PermitUserEnvironment`, `PrintLastLog`, `PubkeyAuthentication`, `StrictModes`, `TCPKeepAlive`, `UsePAM`, `X11Forwarding` | `yes`, `no` |
| `AllowTcpForwarding` | `yes`, `no`, `local`, `remote`, `all` |
| `Compression` | `yes`, `no`, `delayed` |
| `GatewayPorts` | `yes`, `no`, `clientspecified` |
| `PermitRootLogin` | `yes`, `no`, `prohibit-password`, `forced-commands-only` |
| `PermitTunnel` | `yes`, `no`, `point-to-point`, `ethernet` |
| `LogLevel` | `QUIET`, `FATAL`, `ERROR`, `INFO`, `VERBOSE`, `DEBUG`, `DEBUG1`, `DEBUG2`, `DEBUG3` |
| `ClientAliveCountMax` | integer 0-100 |
| `ClientAliveInterval` | integer 0-86400 |
| `LoginGraceTime` | integer 0-3600 |
| `MaxAuthTries` | integer 1-10 |
| `MaxSessions` | integer 1-100 |

A keyword value is matched case-insensitively and rendered in the spelling this
table lists, so the file is byte-identical whichever case the profile used. An
integer keyword also accepts its value as a string, provided the string is a
whole number. The keyword *name* has less slack: the plugin lowercases it before
looking it up, but the schema branch enumerates the canonical spellings above, so
write them as they appear here.

Rendering sorts keywords, so the file is byte-stable across runs. An unstable
render would rewrite the drop-in and reload sshd every time.

### What is deliberately absent

`Port` is not offered. Moving the listener to a port the host firewall may not
accept is a lockout this plugin cannot rule out, because it cannot see the
firewall's ruleset. Until that coordination exists, the port stays where the
host has it.

Keywords that legitimately repeat in one file — `HostKey`, `Subsystem`,
`Match` itself — are also absent. `settings` is a map with one value per
keyword, so it cannot express them, and rejecting them beats mangling them.

## Rollback

The drop-in is journalled as a file snapshot with the unit name alongside it.
Nothing records the running daemon separately: `sshd -T` re-parses the files on
disk rather than asking the running sshd what it holds, so it can only ever
report what the drop-in snapshot already covers.

Rollback restores the file, runs `sshd -t` on the result, and reloads — in that
order and in one step, because a rollback that restores the bytes without
reloading leaves sshd running the policy the rollback just removed from disk.
The journalled unit name is re-checked against the same closed set the schema
accepts before it reaches `systemctl`: a journal is input, not authority.

Rollback fidelity is deterministic.
