# Firewall Plugin

Manages a deterministic nftables include file.

Example:

```json
{
  "id": "firewall-default-deny",
  "plugin": "firewall",
  "config": {
    "backend": "nftables",
    "main_config": "/etc/nftables.conf",
    "family": "inet",
    "table": "filter",
    "managed_dest": "/etc/nftables.d/99-hardline-firewall.nft",
    "policies": [
      { "chain": "input", "policy": "drop" }
    ],
    "rules": [
      {
        "chain": "input",
        "proto": "tcp",
        "port": 22,
        "action": "accept"
      }
    ]
  }
}
```

Config fields, all required:

- `backend`: must be `nftables`. No other backend is accepted
- `main_config`: the file this host's nftables service loads. `/etc/nftables.conf` on Debian-family hosts, `/etc/sysconfig/nftables.conf` on RHEL-family hosts. Those two are the whole accepted set; anything else is rejected at verify
- `family`: `inet`, `ip`, or `ip6`
- `table`: nftables table name
- `managed_dest`: path for the rendered include file. Subject to the same managed-destination rules as the [template plugin](template-plugin.md) — under `/etc/`, normalized, a `99-hardline*` or `00-hardline*` basename, `.conf`/`.nft`/`.rules` extension
- `policies`: at least one chain policy. An empty list is rejected
- `rules`: declarative rule entries

## Policy Fields

| Field | Values |
| --- | --- |
| `chain` | `input`, `output`, `forward` |
| `policy` | `accept`, `drop`, `reject` |

Every chain referenced by a rule must have a matching policy entry, or normalization fails with `missing policy for chain`.

## Rule Fields

| Field | Values | Notes |
| --- | --- | --- |
| `chain` | `input`, `output`, `forward` | Required |
| `action` | `accept`, `drop`, `reject` | Required |
| `proto` | `tcp`, `udp`, `icmp`, `icmpv6`, or omitted | |
| `port` | 1–65535 | Merged with `ports` |
| `ports` | array of 1–65535 | Merged with `port`, deduplicated and sorted |
| `source` | address or CIDR | |
| `destination` | address or CIDR | |
| `in_interface` | interface name | |
| `out_interface` | interface name | |
| `ct_states` | any of `new`, `established`, `related`, `invalid`, `untracked` | Deduplicated |

Field constraints:

- `table` must be an nftables identifier (`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
- `source` and `destination` take one address or one CIDR prefix, matching the table's family; a prefix with host bits set, a range, a named set, or a hostname is refused
- `in_interface` and `out_interface` take an interface name within the kernel's 15-character limit
- a base-chain `policy` is `accept` or `drop`; nft takes nothing else as a chain policy, so `reject` belongs on a rule

Rule constraints:

- `tcp` and `udp` require at least one port; `icmp`, `icmpv6`, and an omitted `proto` must not define any
- every rule must define at least one matcher: a `proto`, `ct_states`, an interface, or an address
- a rule listing several ports expands to one normalized rule per port
- duplicate normalized rules are collapsed silently rather than rejected

Behavior:

- Hardline normalizes and deduplicates the desired ruleset into a deterministic file, so the same config always renders byte-identically. Rules keep the order the profile declared them in, because that is the order the kernel evaluates them: a `drop` written before an `accept` stays before it
- Hardline ensures `main_config` contains `include "<managed_dest>"` — the exact file this step manages — appending the line when absent. Several profiles can own files in one drop-in directory without loading each other's rules, and rollback removes only its own line. A directory-wide `include "<dir>/*.nft"` left by an older hardline is refused, because keeping both would load the same file twice in one transaction
- Hardline ensures the main config starts with `flush ruleset`, so one load produces exactly the ruleset the file describes rather than adding to whatever the kernel already holds. Debian-family configs ship the line; on RHEL-family hosts hardline writes it, and rollback removes it again only if this run added it
- the rendered ruleset is staged as `<managed_dest>.hardline-candidate` and parsed there with `nft -c -f` before it is moved into place, so a file the host cannot load never reaches the path the host loads from; the include is added only after the file exists
- validation runs `nft -c -f <main_config>` on the target
- apply then loads the config with `nft -f <main_config>`: one file, one transaction, so the flush and every table in it commit together and the host is never briefly without rules. A `systemctl restart nftables` would do the same load as stop-then-start, and the stop flushes the ruleset on its own, so a profile needs only `enabled: true` with `state: "started"` for the ruleset to survive a reboot
- after loading, the running table is read back with `nft -j list ruleset` and compared to what was applied, including rule order; a mismatch fails the step
- before loading, a ruleset whose `input` policy is `drop` or `reject` must accept tcp on a port sshd is listening on, or apply refuses rather than locking itself out. The probe fails closed: if the listening port cannot be determined, nothing is loaded
- plan compares both the managed file and, when possible, the running nftables table via `nft -j list ruleset`, and reports a chain whose rules match but evaluate in a different order
- rollback removes the include before the managed file: an include naming a file that is gone fails every later nftables load

## Runtime overrides

The firewall plugin reads two optional overrides from `ctx.Overrides`. A profile must list them in `allowed_overrides` (in `profile.json`) before the CLI will pass them through.

| Override key | Payload | Effect |
| --- | --- | --- |
| `allow_tcp_ports` | JSON array of integers (1–65535) | Appends `accept` rules on the `input` chain for each TCP port |
| `allow_udp_ports` | JSON array of integers (1–65535) | Appends `accept` rules on the `input` chain for each UDP port |

Overrides are loaded from a JSON file via `--overrides-file PATH`, or auto-discovered as `profile.overrides.json` in the profile directory. Hardline does not accept inline `--override key=value` flags on the command line — everything goes through the JSON file. See [Overrides](../users/overrides.md) for the full rules.

Example overrides file (`./runtime/dev-overrides.json`):

```json
{
  "allow_tcp_ports": [8080, 9090],
  "allow_udp_ports": [51820]
}
```

Example CLI invocation against the base profile:

```bash
hardline apply starter-secure-ubuntu-24.04-lts \
  --host example.internal \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --overrides-file ./runtime/dev-overrides.json
```

Overrides are merged into the decoded spec before validation, so invalid ports fail fast and the merged ruleset still produces a deterministic nftables render.
