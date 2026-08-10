# Signing And Verification

Every profile directory is expected to contain:

- `profile.json`
- `manifest.json`
- `manifest.sig`

By default, Hardline verifies signatures using the public key embedded in the binary.

## Use A Local Public Key

Install the public key at:

```text
/etc/hardline/profile_signing_pub.pem
```

Then run commands with:

```bash
--allow-local-key
```

The local key file must not be group-writable or world-writable.

## Generate A Key Pair

```bash
profiletool keygen \
  --private-out ./tmp/profile_signing.key \
  --public-out ./tmp/profile_signing_pub.pem
```

## Sign A Profile

```bash
profiletool sign \
  --profile-dir profiles/starter-secure-ubuntu-24.04-lts \
  --private-key ./tmp/profile_signing.key
```

`keygen` also writes the public key to `internals/verify/profile_signing_pub.pem` relative to the current working directory, regardless of `--public-out`. That is the source-tree path embedded into `hardline` at build time, so run `keygen` from a repo checkout when you are rotating the embedded key, and rebuild Hardline afterwards for the binary to trust it.

Related:

- [Overrides And Signing](../profiles/overrides-and-signing.md)
