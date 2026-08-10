# Profiles

The signed profiles this repository ships. Test fixtures live under
`integration-tests/profiles/` instead; nothing here is a fixture.

| Directory | What it is |
| --- | --- |
| `starter-secure-ubuntu-24.04-lts/` | Ubuntu 24.04 LTS hardening profile, published as its own release tarball |
| `starter-secure-rocky-9/` | The RHEL-family counterpart, published as its own release tarball |
| `demo-profile/` | Five-step profile used for the README demo and quick end-to-end runs; deliberately omits `packages` so a full cycle finishes in about a minute |

Each release tarball is rooted at the profile directory itself, so an extracted
archive is `starter-secure-ubuntu-24.04-lts/`, not `profiles/...`. That is the
form the user guide names.

Every directory here is signed by `make sign-profiles`, which picks them up by
glob along with the integration-test fixtures.
