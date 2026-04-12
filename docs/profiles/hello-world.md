# Hello World Profile

The smallest possible Hardline profile — two files, one step, signed and verifiable in under five minutes. Use this as the skeleton for your own profiles.

For the full authoring reference, see [Profile Structure](structure.md) and [Action Files](action-files.md).

## Goal

Build a profile `hello-world/` that installs a single package (`htop`) on an Ubuntu 24.04 host. Sign it, verify it locally, and optionally apply it to a remote host.

## Prerequisites

- `hardline` and `profiletool` on your `PATH` ([Install Guide](../users/install.md))
- A signing key pair (generated below)

## Step 1 — Directory Layout

Create the profile directory and an `actions/` subdirectory:

```bash
mkdir -p hello-world/actions
```

## Step 2 — `profile.json`

Create `hello-world/profile.json`:

```json
{
  "id": "hello-world",
  "display_name": "Hello World",
  "version": "0.1.0",
  "os": {
    "family": "ubuntu",
    "version": "24.04",
    "variant": "lts"
  },
  "profile_schema": 1,
  "min_hardline": "0.0.1",
  "actions": [
    "actions/10-packages.json"
  ],
  "templates": []
}
```

Every field above is required except `allowed_overrides` (omitted here because this profile has no runtime overrides).

## Step 3 — The Action File

Create `hello-world/actions/10-packages.json`:

```json
{
  "steps": [
    {
      "id": "install-htop",
      "plugin": "packages",
      "config": {
        "install": ["htop"]
      }
    }
  ]
}
```

Notes:

- `id` is any stable string you choose — it shows up in logs and the rollback journal.
- `plugin` must match a registered plugin. `packages`, `template`, `service`, and `firewall` are built in.
- `config` is plugin-specific. See [Packages Plugin](packages-plugin.md) for all fields.

## Step 4 — Sign The Profile

Generate a signing key pair once and keep it under `/etc/hardline` alongside the binaries — the [Install Guide](../users/install.md#profile-signing-key-optional) explains why this directory is the right home for it. Skip this block if you already have a keypair there.

```bash
sudo profiletool keygen \
  --private-out /etc/hardline/profile_signing.key \
  --public-out  /etc/hardline/profile_signing_pub.pem

sudo chmod 0600 /etc/hardline/profile_signing.key
sudo chmod 0644 /etc/hardline/profile_signing_pub.pem
```

Sign the profile:

```bash
sudo profiletool sign \
  --profile-dir hello-world \
  --private-key /etc/hardline/profile_signing.key
```

`profiletool sign` writes `manifest.json` (hashes of every file in the directory) and `manifest.sig` (signature over the manifest) into `hello-world/`.

Your directory now looks like:

```text
hello-world/
  profile.json
  manifest.json
  manifest.sig
  actions/
    10-packages.json
```

## Step 5 — Verify

Because the signing key you just generated is not the one embedded in a prebuilt `hardline` binary, you need to tell Hardline to trust your key. The public half is already at `/etc/hardline/profile_signing_pub.pem` from Step 4 — which is exactly where `--allow-local-key` looks.

Verify the profile against the local key:

```bash
hardline verify-profile hello-world --allow-local-key
```

If you built `hardline` from source using the same key, `--allow-local-key` is unnecessary — the binary already trusts the embedded key.

A successful verify prints the profile's ID, the action files it walked, and confirms plugin availability. No SSH connection is attempted.

## Step 6 — Plan (Optional)

Point at an Ubuntu 24.04 host:

```bash
hardline plan hello-world \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --allow-local-key
```

`plan` connects, checks the OS, queries current package state, and tells you whether `htop` is already installed. It does not mutate the host.

## Step 7 — Apply (Optional)

When you're ready to install:

```bash
hardline apply hello-world \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --allow-local-key
```

Hardline verifies, plans, acquires the apply lock, captures pre-state, installs `htop`, captures post-state, and persists a rollback journal on the target.

## Step 8 — Roll Back (Optional)

Undo the apply with:

```bash
hardline rollback hello-world \
  --host example.com \
  --user ubuntu \
  --keypath ~/.ssh/id_ed25519 \
  --allow-local-key
```

The packages plugin captured that `htop` was not installed before the apply, so rollback will `purge` it. If someone installed another package `htop` depends on between apply and rollback, the conflict check stops the rollback — that is intentional. See [Failure And Recovery](../users/failure-and-recovery.md#rollback-conflicts).

## Next Steps

- Add a template step ([Template Plugin](template-plugin.md)) — note the managed destination rules: under `/etc/`, basename starts with `99-hardline`, extension `.conf` / `.nft` / `.rules`.
- Add a service step with a restart policy ([Service Plugin](service-plugin.md)).
- Expose a runtime knob via `allowed_overrides` ([Overrides](../users/overrides.md)).
- Bolt down the firewall ([Firewall Plugin](firewall-plugin.md)).

Every time you edit any file in the profile directory, re-run `profiletool sign` before verifying or applying. Manifest hashes are over file bytes, so even a whitespace change invalidates the signature.
