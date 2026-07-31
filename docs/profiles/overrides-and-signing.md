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
profiletool keygen \
  --private-out ./tmp/profile_signing.key \
  --public-out ./tmp/profile_signing_pub.pem
```

Sign a profile:

```bash
profiletool sign \
  --profile-dir ./my-profile \
  --private-key ./tmp/profile_signing.key
```

`sign` also takes `--manifest-out` and `--sig-out`; they default to `<profile-dir>/manifest.json` and `<profile-dir>/manifest.sig`.

The generated manifest includes all regular files under the profile directory, recursively, except:

- `manifest.json`
- `manifest.sig`
- `profile.overrides.json`

Anything else that is not a regular file — a symlink, socket, or device node — aborts the walk with `unsupported non-regular profile file`, during both signing and verification.

Verification is stricter than a file list check. On top of matching every recorded SHA-256, `verify-profile` rejects a profile directory that contains a file the manifest does not list, and separately asserts that every path in `profile.json`'s `actions` and `templates` arrays is covered by the signed manifest. A signed pointer to unsigned content is not accepted.
