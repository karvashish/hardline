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

Config fields:

- `backend`: currently `nftables`
- `family`: `inet`, `ip`, or `ip6`
- `table`: nftables table name
- `managed_dest`: path for the rendered include file
- `policies`: chain policies
- `rules`: declarative rule entries

Behavior:

- Hardline normalizes and sorts the desired ruleset into a deterministic file
- Hardline ensures `/etc/nftables.conf` includes `/etc/nftables.d/*.nft`
- plan compares both the managed file and, when possible, the running nftables table

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
hardline apply base-secure-ubuntu-24.04-lts \
  --host example.internal \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --overrides-file ./runtime/dev-overrides.json
```

Overrides are merged into the decoded spec before validation, so invalid ports fail fast and the merged ruleset still produces a deterministic nftables render.
