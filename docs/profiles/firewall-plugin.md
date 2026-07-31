# Firewall Plugin

Manages a deterministic nftables include file.

Example:

```json
{
  "id": "firewall-default-deny",
  "plugin": "firewall",
  "config": {
    "backend": "nftables",
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
- `family`: `inet`, `ip`, or `ip6`
- `table`: nftables table name
- `managed_dest`: path for the rendered include file. Subject to the same managed-destination rules as the [template plugin](template-plugin.md) — under `/etc/`, normalized, `99-hardline*` basename, `.conf`/`.nft`/`.rules` extension
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

Rule constraints:

- `tcp` and `udp` require at least one port; `icmp`, `icmpv6`, and an omitted `proto` must not define any
- every rule must define at least one matcher: a `proto`, `ct_states`, an interface, or an address
- a rule listing several ports expands to one normalized rule per port
- duplicate normalized rules are collapsed silently rather than rejected

Behavior:

- Hardline normalizes, deduplicates, and sorts the desired ruleset into a deterministic file, so the same config always renders byte-identically
- Hardline ensures `/etc/nftables.conf` contains `include "/etc/nftables.d/*.nft"`, appending the line when absent
- validation runs `nft -c -f /etc/nftables.conf` on the target
- plan compares both the managed file and, when possible, the running nftables table via `nft -j list ruleset`
- rollback restores `/etc/nftables.conf` before the managed file, so the include is reverted in the right order

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
