# Overrides

Hardline supports runtime overrides as a JSON object.

You can load overrides in either of two ways:

1. pass an explicit file with `--overrides-file`
2. place `profile.overrides.json` inside the profile directory and let Hardline auto-discover it

Example — opening two extra TCP ports and one UDP port in the base profile's firewall:

```json
{
  "allow_tcp_ports": [8080, 9090],
  "allow_udp_ports": [51820]
}
```

Important details:

- override keys must be listed in `allowed_overrides` in `profile.json`
- the auto-discovered file name is exactly `profile.overrides.json`
- `profile.overrides.json` is excluded from the signed manifest
- plugins must explicitly read override values to make use of them — the built-in firewall plugin consumes `allow_tcp_ports` and `allow_udp_ports`

Use an explicit overrides file like this:

```bash
hardline plan base-secure-ubuntu-24.04-lts \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --overrides-file ./runtime/dev-overrides.json
```

Related:

- [Profile Structure](../profiles/structure.md)
- [Overrides And Signing](../profiles/overrides-and-signing.md)
