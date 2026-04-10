# Overrides And Signing

## Runtime Overrides

Overrides are loaded from either:

- `--overrides-file <path>`
- `profile.overrides.json` inside the profile directory

The overrides payload must be a JSON object. Example — opening extra TCP ports in the base profile's firewall step:

```json
{
  "allow_tcp_ports": [8080, 9090]
}
```

Key points:

- only keys declared in `allowed_overrides` are accepted
- `profile.overrides.json` is excluded from the signed manifest
- plugins must explicitly read `ctx.Overrides` if they want to use override values; the built-in firewall plugin consumes `allow_tcp_ports` and `allow_udp_ports`

## Signing

Generate a key pair:

```bash
tmp/profiletool keygen \
  --private-out ./tmp/profile_signing.key \
  --public-out ./tmp/profile_signing_pub.pem
```

Sign a profile:

```bash
tmp/profiletool sign \
  --profile-dir ./my-profile \
  --private-key ./tmp/profile_signing.key
```

The generated manifest includes all regular files under the profile directory except:

- `manifest.json`
- `manifest.sig`
- `profile.overrides.json`
