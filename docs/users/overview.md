# Overview

Hardline is a signed-profile runner for applying opinionated system configuration to remote Linux hosts over SSH.

At a high level, Hardline:

1. verifies the profile signature and manifest
2. validates the profile schema and required plugins
3. connects to the remote host over SSH
4. checks the remote OS against the profile
5. plans or applies steps in order
6. records rollback data so the last successful apply can be reverted

The main CLI commands are:

- `verify-profile`
- `plan`
- `apply`
- `rollback`
- `version`

The sample profiles in this repo target Ubuntu 24.04 LTS and Rocky Linux 9, and include base hardening for:

- packages
- SSH
- unattended upgrades
- sysctl
- timesync
- firewall
- fail2ban
- auditd
- journald

Next:

- [Getting Started](getting-started.md)
