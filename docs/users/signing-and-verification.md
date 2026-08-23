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

That file is a trust anchor, so on Linux and macOS Hardline opens it with `O_NOFOLLOW` and checks the descriptor it is about to read rather than the path: it must be a regular file, not a symlink, owned by root, and neither group-writable nor world-writable (`0644` or stricter). Anyone who could replace it could choose which profiles verify.

On Windows, neither the `O_NOFOLLOW` open nor the root-owner check has an equivalent, so the key is opened normally and the owner check is skipped. The regular-file and permission checks still run. If you need the full trust-anchor guarantees, verify from a Unix runner, or stay on the embedded key - it is compiled into the binary and read from disk on no platform.

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
