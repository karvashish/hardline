# Profiles

This page describes the profile format implemented in `pkg/profile`, `pkg/pluginapi`, and `internals/verify`.

## Directory layout

A profile directory contains:

- `profile.json`
- one or more action files referenced by `profile.json`
- zero or more template files referenced by `profile.json`

If you want signature verification through `verify-profile`, the directory also needs:

- `manifest.json`
- `manifest.sig`

## `profile.json`

The `Profile` struct currently contains these fields:

- `id`
- `display_name`
- `version`
- `os`
  - `family`
  - `version`
  - `variant`
- `profile_schema`
- `min_hardline`
- `actions`
- `templates`

Example from `base-secure-ubuntu-24.04-lts/profile.json`:

```json
{
  "id": "base-secure-ubuntu-24.04-lts",
  "display_name": "Base Secure Ubuntu 24.04 LTS",
  "version": "1.0.0",
  "os": {
    "family": "ubuntu",
    "version": "24.04",
    "variant": "lts"
  },
  "profile_schema": 1,
  "min_hardline": "0.0.1",
  "actions": [
    "actions/00-packages.json",
    "actions/10-ssh.json"
  ],
  "templates": [
    "templates/10-ssh-sshd-config.tmpl"
  ]
}
```

## Action files

Each action file decodes into:

```json
{
  "steps": [
    {
      "id": "step-id",
      "plugin": "template",
      "severity": "low",
      "risk_class": "integrity",
      "control_tags": [],
      "config": {},
      "allow_unvalidated": false
    }
  ]
}
```

Current step fields:

- `id`
- `plugin`
- `severity`
  - `low`
  - `medium`
  - `high`
  - `critical`
- `risk_class`
  - `none`
  - `access`
  - `availability`
  - `data_loss`
  - `integrity`
  - `compliance`
  - `other`
- `control_tags`
- `config`
- `allow_unvalidated`

## Validation layers

### Schema validation

`plan` and `apply` both call `Profile.Affirm()`.

That validates:

- `profile.json` against `schema/profile.schema.json`
- every listed action file against `schema/action-file.schema.json`

### Plugin validation

After schema validation, Hardline ensures every step plugin is registered.

### Signature validation

`verify-profile` separately validates:

- `manifest.json`
- `manifest.sig`
- hash coverage for every non-metadata file in the profile directory

`plan` and `apply` do not run this signature-validation step.

## Template declaration rules

Templates are loaded through `Profile.LoadTemplate(rel)`.

That means:

- template paths are relative to the profile directory
- a template must be listed in `profile.json.templates`
- loading a template not declared there fails

## Version gating

Two version checks happen before `plan` and `apply` continue:

- Hardline version must satisfy `min_hardline`
- `profile_schema` must not be newer than the compiled-in supported schema version

## OS metadata

The `os` object is stored in the profile and appears in plan reports.

The current code does not enforce host OS compatibility from these fields.

## Example profile patterns in this repo

User-facing profile:

- `base-secure-ubuntu-24.04-lts`

Integration-only profiles:

- `integration-tests/profiles/multi-plugin-success`
- `integration-tests/profiles/multi-plugin-force-rollback`
- `integration-tests/profiles/package-rollback`
- `integration-tests/profiles/layer-base`

## Manifest generation and signing

The profile signing tool does two things:

- `keygen`
  - generates an Ed25519 keypair
  - writes the public key to `internals/verify/profile_signing_pub.pem`
- `sign`
  - hashes every non-metadata file in the profile directory
  - writes `manifest.json`
  - signs that manifest into `manifest.sig`

Useful commands:

```bash
make profiletool
make sign-profile PROFILE_DIR=base-secure-ubuntu-24.04-lts
make sign-profiles
```
