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
  --profile-dir base-secure-ubuntu-24.04-lts \
  --private-key ./tmp/profile_signing.key
```

If you want the binary itself to trust a rotated embedded key, rebuild Hardline after key generation.

Related:

- [Overrides And Signing](../profiles/overrides-and-signing.md)
