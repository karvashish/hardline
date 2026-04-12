# Changelog

All notable changes to Hardline are documented in this file.

The format follows [Keep A Changelog](https://keepachangelog.com/en/1.1.0/), and versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once the project reaches 1.0. Until then, breaking changes may occur on any minor version — check this file before upgrading.

## [Unreleased]

### Added

- Release pipeline: tag-triggered GitHub Actions workflow that builds `hardline` and `profiletool` for linux amd64/arm64 and windows amd64/arm64, packages the `starter-secure-ubuntu-24.04-lts` profile as a tarball, and publishes all artifacts to a GitHub Release with SHA256 companions.
- `make build-windows` target for cross-compiling static (CGO-disabled) Windows binaries. External plugins remain Linux-only.
- User-facing [Install Guide](docs/users/install.md) covering tarball download, verification, extraction, and PATH setup for Linux and Windows.
- [CLI Reference](docs/users/cli-reference.md) documenting every command, flag, environment variable (`HARDLINE_KNOWN_HOSTS`, `HARDLINE_STATE_DIR`), and exit code.
- [Failure And Recovery](docs/users/failure-and-recovery.md) covering SIGINT behavior, SSH drops mid-apply, stuck apply locks, partial applies, and rollback conflicts.
- [Hello World Profile](docs/profiles/hello-world.md) tutorial for authors.
- `SECURITY.md` with disclosure path and trust-boundary notes.
- README: Platform Support table, Supported Targets section (explicit non-Ubuntu disclaimer).

### Changed

- User docs now reference `hardline` / `profiletool` directly instead of `tmp/hardline` / `tmp/profiletool`, matching the prebuilt-release install path. The Build From Source section in Getting Started still mentions the `tmp/` output.
- Troubleshooting page expanded, including SSH handshake mismatches, sudo edge cases, signature verification failures, apt/dpkg lock contention, and report-file errors.
- [Firewall Plugin](docs/profiles/firewall-plugin.md) override example corrected. The previous example showed `--profile-dir` and `--override key=value` flags that the CLI does not accept; the example now uses `--overrides-file` against a JSON file.

## [0.1.0-rc1] - 2026-04-12

Initial release candidate. First tagged build.

[Unreleased]: https://github.com/karvashish/hardline/compare/v0.1.0-rc1...HEAD
[0.1.0-rc1]: https://github.com/karvashish/hardline/releases/tag/v0.1.0-rc1
