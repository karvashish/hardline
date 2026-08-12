# OS Hardening Capability Gap Report

Audit basis: Hardline commit `c8c9403d80180458b24aa7ca8bf85c53a283525b`, reviewed 2026-08-10.

Intended public profiles:

- `os-hardening-ubuntu-24.04-lts`, using `packages_apt`
- `os-hardening-fedora-44`, using `packages_dnf5`

This is a read-only design and capability audit. It does not claim CIS compliance, alignment, certification, sponsorship, or endorsement. The proposed profiles are independently authored, MIT-licensed Hardline content with sources recorded as engineering references.

## Executive conclusion

Hardline can express a useful conservative hardening subset, but it cannot yet safely support either proposed profile at the intended full-profile level.

The main issue is not the absence of generic commands. Hardline's fixed typed vocabulary is the correct security boundary. The audit found:

- One critical signed-profile trust flaw affecting every profile.
- Several high-risk rollback, validation, package, firewall, and change-detection defects.
- Missing typed operations for authentication, mandatory-access control, native Fedora firewalling, boot state, mounts, integrity monitoring, and dynamic file/account checks.
- Requirements that properly belong to provisioning or site policy and should not be forced into Hardline.

## Current expressible surface

After the core safety defects in this report are fixed, existing built-ins can support:

- Named APT, DNF4, and DNF5 package installation and removal.
- Metadata refresh, full upgrade, and autoremove cadence, with limited rollback.
- Static, signed, Hardline-named `/etc` drop-ins.
- Basic systemd enable/disable/start/stop/restart behavior.
- Conservative sysctl configuration through `sysctl.d`.
- Journald and similar valid `.conf.d` fragments.
- Exact metadata on known, existing files.
- Static audit rule files.
- Raw nftables configuration.
- Static SSH drop-ins, although not yet safe to activate.

DNF5 itself is already implemented. Fedora 44 uses DNF5; the executable being named `dnf` does not make this a DNF4 profile. Fedora has used DNF5 as the default since Fedora 41. See the [Fedora DNF5 change](https://fedoraproject.org/wiki/Changes/SwitchToDnf5).

The intended trust boundary is documented in the [README](../README.md): profiles have no arbitrary `exec`, `command`, or `script`.

## Priority definitions

- **P0:** release blocker for all profiles, or every profile using the affected domain.
- **P1:** high-risk correctness or coverage issue that must be fixed or explicitly excluded.
- **P2:** assurance or broader-coverage improvement.
- **OUT:** provisioning, lifecycle, or organization-specific responsibility rather than a Hardline mutation capability.

## Engine correctness and trust gaps

| ID | Priority | Missing or defective capability | Consequence and required correction |
| --- | --- | --- | --- |
| E01 | **P0** | Immutable verified profile bundle | Integrity verification hashes profile files but returns only the manifest digest and path set. Profile/actions are loaded afterward, templates later, and apply rechecks only `manifest.json`. A local writer can replace signed payload bytes after verification without changing the manifest. Consume an immutable snapshot of the exact authenticated bytes throughout verify, plan, and apply. Evidence: [`internals/verify/integrity.go`](../internals/verify/integrity.go), [`internals/verify/verify.go`](../internals/verify/verify.go), and [`internals/apply/apply.go`](../internals/apply/apply.go). |
| E02 | **P0 when overrides are used** | Immutable runtime override snapshot | Unsigned overrides are independently reread during verify, plan, and apply. Apply can therefore use firewall ports different from the displayed plan. Resolve once, hash/snapshot them, and reject drift. |
| E03 | **P0 for firewall** | Security-preserving firewall order | Rules are sorted by `chain\|action\|...`, putting `accept` before `drop`. An invalid-state or anti-spoof drop can execute after service accepts. Add signed priorities or preserve declared order with stable rule IDs. Evidence: [`internals/plugins/firewall/execution.go`](../internals/plugins/firewall/execution.go). |
| E04 | **P0 for firewall** | Prospective validation and live activation | Table, interface, source, and destination fields are insufficiently parsed and can carry unintended nft grammar. `reject` is accepted as a base-chain policy although nft supports `accept`/`drop`. Validation occurs after files are written, and firewall apply does not itself activate live rules. Strictly parse fields, stage and `nft -c` the complete candidate before mutation, then atomically activate and verify live ordered rules. |
| E05 | **P0 for SSH** | SSH candidate validation and effective-state verification | A template can write an SSH drop-in and the service plugin can reload it, but there is no `sshd -t` before activation, `sshd -T` verification, Match-context evaluation, or management-access guard. Add a typed SSH plugin with candidate validation, atomic restoration, reload, and effective-key checks. |
| E06 | **P0 for audit rules** | Exact audit-rule verification and brownfield preflight | The audit plugin verifies keys only. A different rule with the same key false-passes. It does not preflight absent watches, conflicting `-D`, existing `-e 2`, duplicate keys, or complete rule equivalence. Compare normalized rule bodies and reject destructive/immutable policy in a rollback-capable run. |
| E07 | **P1** | Atomic rollback conflict preflight | Explicit rollback checks a step and immediately restores it. A later conflict can be found only after other steps were already reverted. Check all applicable conflicts before the first mutation. Evidence: [`internals/rollback/rollback.go`](../internals/rollback/rollback.go). |
| E08 | **P1** | Cancellation after a running step | Cancellation is checked before each step, not after it or before committing success. SIGINT during the last step can be ignored if the command subsequently succeeds. Recheck context after every step and before journal finalization. |
| E09 | **P1** | Complete change accounting | Shared change detection ignores file mode, package version and transaction effects. Upgrade-only or autoremove-only package steps may capture no objects. Mode-only changes can be reported `ALIGNED` and fail to trigger `restart_policy:on_change`. Use plugin-owned semantic change results or complete typed snapshots. Evidence: [`pkg/pluginapi/helpers.go`](../pkg/pluginapi/helpers.go). |
| E10 | **P1** | Recoverable journal commit failure | A host may be fully changed before its remote journal save fails. The CLI returns failure and stores a local fallback, but explicit rollback reads only the remote journal. Either auto-rollback, complete an atomic/retryable remote commit, or support strongly bound local-journal recovery. |
| E11 | **P1** | Fail-closed package probing | Package query errors are treated as "not installed"; lock-probe errors are treated as "unlocked." A transport/backend error can produce a false rollback snapshot. Use tri-state results and recognize only the backend's exact not-installed response. |
| E12 | **P0 if purge is used** | Removal transaction preview | Direct APT/DNF purge does not preview collateral dependency removal. Conservative public profiles should have no purge until plan shows the complete removal transaction and requires explicit authorization for collateral packages. |
| E13 | **P1** | Verify-time plugin semantic validation | `verify-profile` checks schema and plugin availability, but does not execute each built-in's pure decoder/validator. Most plugin schemas are open, and JSON decoding ignores unknown keys. Typos can verify successfully and fail or be ignored later. Close schemas, disallow unknown fields, and run semantic validation during verify. Evidence: [`pkg/profile/profile.go`](../pkg/profile/profile.go) and [`internals/verify/verify.go`](../internals/verify/verify.go). |
| E14 | **P1** | Step graph validation | IDs are not globally checked for nonempty uniqueness. Restart dependencies need not exist, precede their consumer, be unique, or avoid self-reference. Duplicate IDs overwrite change maps and make rollback dependency lookup ambiguous. |
| E15 | **P1** | Exact systemd state capture | Service state is reduced to enabled/active booleans. Masked, static, indirect, generated, failed, and transient states cannot round-trip. Query errors can also become false state. Capture exact unit-file and active state and restore only semantically valid transitions. |
| E16 | **P1** | Strict restart-policy enum | Any restart policy other than `always` behaves roughly like `on_change`; the value and dependency list are not fully validated. Restrict it to a closed enum and validated graph. |
| E17 | **P1** | Complete file conflict and rollback fidelity | Generic file conflict detection ignores mode and treats "journal says absent, file now exists" as no conflict. File snapshots also omit owner/group, symlink identity, ACLs, xattrs, and SELinux context. At minimum compare existence, content, mode, file type, and identity. Evidence: [`pkg/pluginapi/helpers.go`](../pkg/pluginapi/helpers.go). |
| E18 | **P1** | Bounded, symlink-safe file capture | Remote file capture follows target paths and reads the entire file without regular-file or size checks. A compromised host can substitute a symlink, device, or huge file. Require non-symlink regular files, bounded size, and inode checks. |
| E19 | **P1** | External plugin artifact trust | External `.so` files run as root and are unsigned. The loader checks only whether the directory is world-writable; it does not enforce documented ownership, group-write, regular-file, symlink, or individual artifact constraints. New baseline capabilities should be reviewed built-ins unless this is fixed. Evidence: [`internals/plugins/loader.go`](../internals/plugins/loader.go). |
| E20 | **P1** | Shared mutation lock | Apply takes a remote lock; explicit rollback does not. They can overlap. Both must use one host mutation lock. |
| E21 | **P2** | Honest rollback result and journal lifecycle | Automatic rollback can swallow best-effort package failures while reporting completion. Journal checksum/identity validation is permissive, journal deletion failure can leave an already-consumed journal reusable, and filename selection is loose. Aggregate degraded restoration and make journal validation/consumption transactional. |
| E22 | **P2** | Strict parsing and resource bounds | Template mode parsing accepts partial/out-of-range values, and template diff uses unbounded quadratic line comparison. Parse modes strictly and bound diff size/work. |
| E23 | **P1** | Accurate eligibility and rollback reporting | `os.variant` is signed and required but never checked; no architecture, server/workstation, container, firewall-manager, or maintenance-state preconditions exist. Plan also reports rollback "available" for irreversible or best-effort transactions. Enforce eligibility and report deterministic/best-effort/irreversible truthfully. |

## Missing typed hardening capabilities

These are absent operations, not demands to add a generic command escape hatch.

| Capability | What is missing | Needed by | Priority |
| --- | --- | --- | --- |
| Semantic plugin state | Journalable runtime state beyond file/service/package booleans, such as SELinux mode, mount options, or crypto-policy state | Both | P0 foundation for new plugins |
| Assert versus ensure mode | Typed plugins should be able to verify prerequisites without mutating them | Both | P0 foundation |
| Structured reboot outcome | `reboot_required`, reason, and effective-after state; conservative profiles should never reboot automatically | Both | P1 |
| Advanced systemd | Mask/unmask, daemon-reload, reload-only, unit presence, timer handling, and exact-state rollback | Both | P1 |
| Validated daemon configuration | Narrow ownership, candidate parsing, atomic activation, and effective-state verification | Both | P0/P1 by domain |
| Package transaction policy | Removal preview, security-scoped upgrades, transaction health, and truthful irreversibility | Both | P0/P1 |
| Repository trust | Effective repository/signature/TLS/key/origin assertions and approved repository allow-list | APT and DNF5 | P1/site |
| Scheduled DNF5 updates | Manage/assert `/etc/dnf/automatic.conf`, upgrade scope, apply/download/reboot behavior, and timer | Fedora | P1 |
| Native firewalld | Manager ownership, zones, services/ports, interfaces, permanent/runtime parity, and lockout-safe reload | Fedora | P0 |
| SSH policy | `sshd -t`, `sshd -T`, Match contexts, safe activation, and host-key discovery | Both | P0 |
| PAM/authentication policy | Ubuntu `pam-auth-update`; Fedora `authselect`; faillock, history, and effective module ordering | Both, distro adapters | P0 |
| Sudo policy | Extensionless include, `visudo -cf`, fixed ownership/mode, and rollback | Both | P0 when claimed |
| Existing-account policy | Empty hashes, ageing, lock state, UID/GID consistency, shells, homes, and explicit exclusions | Both | P1/site |
| AppArmor | Kernel/profile status, enforce/complain inventory, and allow-listed transitions | Ubuntu | P1 |
| SELinux | Runtime/persistent mode, targeted policy, boot-bypass detection, and safe permissive-to-enforcing transition | Fedora | P0 |
| Fedora crypto policy | `update-crypto-policies --show/--check/--is-applied/--set`, semantic rollback, and restart notice | Fedora | P0 |
| Effective sysctl verification | Structured keys, candidate parsing, live readback, and missing-key handling | Both | P1 assurance |
| Mount policy | Topology and option assertion; optional structured fstab/remount handling | Both | P1/assert-first |
| Kernel modules | Applicability, persistent disable, loaded/dependency checks, and optional safe unload | Both | P1 |
| Kernel arguments and boot | Ubuntu GRUB and Fedora BLS/grubby semantics, future defaults, and reboot state | Both | P1 |
| Integrity monitoring | AIDE initialization, database state, config validation, fixed timer, and check status | Both | P1 |
| Dynamic file policy | Bounded non-symlink discovery for logs, audit files, homes, unowned/world-writable, and SUID/SGID objects | Both | P1 assertion; P2 remediation |
| Scheduler access | Create extensionless `cron.allow`/`at.allow` and remove deny files safely | Ubuntu and possibly Fedora | P1 |
| Banners and shell policy | Exact issue/MOTD files and validated `.sh` profile fragments | Ubuntu/source-dependent | P1 |
| Time synchronization | Typed chrony config, candidate validation, and optional synchronization assertion | Both | P1 |
| Logging policy | Rsyslog/logrotate validation, dynamic log metadata, and typed remote destination inputs | Both | P1/P2 |
| Service/socket inventory | Assert only approved listeners and managers from a site-supplied allow-list | Both | Site/P1 |
| Source/coverage ledger | Independent control ID, source/version/date, desired state, action IDs, and explicit disposition | Both | Documentation release gate |

The narrow template boundary should remain. Many security consumers intentionally ignore filenames that look valid to Hardline:

- Ubuntu sudoers ignores names containing `.`.
- `/etc/profile.d` expects `.sh`.
- systemd expects `.service` and `.timer`.
- GRUB commonly expects `.cfg`.
- cron/PAM access files are often extensionless.

Relaxing the generic template path check would create more signed root-write surface without adding the consumer-specific parser and activation safety these files require.

## Ubuntu 24.04 impact

The authoritative CIS Ubuntu landing page currently identifies Ubuntu Linux 24.04 Benchmark v2.0.0. The public Ansible Lockdown Ubuntu 24 role is still documented against v1.0.0, so it cannot establish current v2 completeness. It can only be a behavioral cross-check.

Sources:

- [CIS Ubuntu 24.04](https://www.cisecurity.org/benchmark/ubuntu_linux)
- [Ansible Lockdown Ubuntu releases](https://github.com/ansible-lockdown/UBUNTU24-CIS/releases)

### Expressible after core fixes

- Conservative APT package posture without purge/autoremove.
- Static unattended-upgrades configuration.
- Safe sysctl subset.
- Journald persistence and limits.
- Fixed known-file metadata.
- Package/service presence for AppArmor, chrony, AIDE, and auditd, although presence alone does not satisfy their effective controls.
- Raw nftables, only after ordering, staging, and activation are fixed.
- SSH settings, only after typed validation is added.
- Static additive audit rules, only after exact verification and brownfield checks are added.

### Missing for broad Ubuntu OS-hardening coverage

- Ubuntu PAM stack ownership through `pam-auth-update`.
- Effective faillock, password history, and password-quality module ordering.
- Extensionless sudoers include plus `visudo`.
- AppArmor effective enforcement.
- AIDE initialization and recurring checks.
- Audit daemon configuration and dynamic/optional rules.
- Cron/at allow-deny files.
- Console/MOTD banners.
- Valid shell `UMASK`/`TMOUT` fragment.
- APT repository/key/origin approval.
- Account-age, lock, home, and UID/GID assertions.
- Dynamic audit/log/SSH-key metadata.
- Mount, kernel-module, and boot-state assertions.

Separate partitions, storage encryption, admin-user/key creation, boot passwords, allowed services, identity groups, NTP endpoints, log endpoints, and legal banner wording remain provisioning or site decisions.

## Fedora 44 impact

There is no current CIS Fedora 44 Benchmark in the active CIS catalog. The last official Fedora benchmark evidence is historical Fedora 28 material, which is obsolete for Fedora 44. Therefore the Fedora profile must be independently sourced from Fedora and upstream documentation; it must not make a CIS compliance or alignment claim.

Sources:

- [Current CIS catalog](https://www.cisecurity.org/cis-benchmarks)
- [Historical Fedora 28 reference](https://www.cisecurity.org/insights/blog/cis-benchmarks-november-2020-update)

### Expressible after core fixes

- Named package management through `packages_dnf5`.
- Conservative manual full-upgrade behavior, explicitly best-effort and non-reversible.
- Installation and enablement of `dnf5-plugin-automatic`, although not its effective policy.
- Journald configuration.
- Safe sysctl subset.
- Chronyd package/service presence.
- Fixed existing-file metadata.
- SSH, audit, and raw nftables only after their core fixes.

### Fedora-specific blockers

- **Firewalld:** a conservative Fedora profile should preserve the native firewalld/nftables arrangement. Current Hardline can only replace it with raw nftables. That takeover is materially disruptive and must be explicit, not the default.
- **SELinux:** no assertion or enforcement of runtime/persistent targeted enforcing state; no boot-bypass detection.
- **Crypto policies:** no `DEFAULT` policy assertion or applied-state verification.
- **Authselect/PAM:** generated PAM files must not be templated directly.
- **DNF5 automatic:** exact policy, security-only scope, and reboot behavior are unmanaged. DNF5's default automatic configuration downloads updates but does not apply them unless configured. See the [DNF5 automatic documentation](https://dnf5.readthedocs.io/en/stable/dnf5_plugins/automatic.8.html).
- **DNF5 repository trust:** no final effective per-repository signature/TLS/key assertion.
- **Chrony:** service presence does not prove trusted sources or synchronization.
- **Audit:** exact runtime rules, `auditd.conf`, early-boot audit, and dynamic privileged executables are unsupported.
- **Fedora BLS/kernel arguments:** no safe grubby/BLS operation or reboot-required result.
- **Mounts, modules, AIDE, accounts, and dynamic file checks:** same general gaps as Ubuntu.

A full Fedora profile should not ship until firewalld, or an explicitly documented raw-nftables ownership decision, plus SELinux, crypto-policy, and authselect assertions are available.

## Correctly outside Hardline's mutation boundary

These should be documented or asserted, not automatically fixed by a generic public profile:

- Creating, resizing, or repartitioning filesystems.
- LUKS or other disk encryption.
- BIOS/UEFI configuration and Secure Boot enrollment.
- Creating the administrative account or distributing its SSH key.
- Choosing MFA, SSSD, winbind, smart-card, or directory-login design.
- Choosing allowed ports, listeners, server roles, and account exclusions.
- Choosing NTP/NTS and remote-log endpoints, certificates, or credentials.
- Legal banner wording.
- Automatically rebooting the host.
- Blindly disabling IPv6, strict reverse-path filtering, forwarding, overlay/squashfs, USB, or application-required modules.
- Generic world-writable/unowned-file remediation without workload-specific policy.
- Desktop/GDM controls in server profiles.
- Generic profile-level `exec`, loops, shell snippets, or arbitrary discovery/action language.

Typed assert-only operations are still useful for many of these. For example, Hardline can assert that `/var/log/audit` is a separate filesystem while leaving its creation to Terraform or image building.

## Minimum release gates

### Gate A: all profiles

Before publishing either `os-hardening-*` profile:

1. Fix the verified-payload time-of-check/time-of-use flaw.
2. Snapshot runtime overrides between plan and apply.
3. Preflight all rollback conflicts and share the mutation lock.
4. Correct change detection and file conflict semantics.
5. Make remote journal commit failure recoverable.
6. Fail closed on package query errors.
7. Add purge transaction previews or omit purge.
8. Close plugin schemas and validate all steps and dependencies during verify.
9. Report real rollback fidelity and reboot requirements.

### Gate B: domains used by both profiles

1. Fix firewall rule ordering, input validation, pre-write candidate testing, and live activation.
2. Add validated SSH configuration and reload.
3. Strengthen audit rule equivalence and brownfield handling if audit rules remain.
4. Add a signed source/coverage ledger.

### Gate C: Ubuntu full-profile scope

Either implement PAM, sudoers, and AIDE lifecycle support, or mark them visibly `deferred`. AppArmor, mounts, modules, accounts, repository trust, and dynamic file checks must each be `implemented`, `asserted_prerequisite`, `site_required`, `provisioning`, `deferred`, or `not_applicable`.

### Gate D: Fedora full-profile scope

Implement Fedora-native firewalld, SELinux, crypto-policy, and authselect assertion/remediation. Add DNF5 automatic/repository policy if the profile promises enforced update or repository posture.

## Source and claims model

Each control should carry something equivalent to:

```text
hardline_id
desired_state
source_title
source_url
source_version_or_commit
retrieved_at
implementation_actions
status
tests
copied_code: false
```

Valid status values should be:

```text
implemented
asserted_prerequisite
site_required
provisioning
deferred
not_applicable
```

Recommended profile wording:

> Independently developed OS hardening profile based on documented operating-system and upstream software behavior. Source citations identify engineering references only. This profile is not a CIS Benchmark and makes no claim of CIS compliance, certification, sponsorship, or endorsement.

The existing `starter-secure-*` profiles can remain lower-scope starters. They do not all need to be raised to OS-hardening scope, but the common engine defects, especially verified-byte integrity and firewall ordering, affect them too and must be corrected.
