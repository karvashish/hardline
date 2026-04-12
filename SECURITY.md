# Security Policy

## Reporting A Vulnerability

If you believe you have found a security vulnerability in Hardline, **please do not open a public issue**. Reports made in public before a fix is available put every user of the tool at risk.

Preferred channels, in order:

1. **GitHub private security advisory** — use the "Report a vulnerability" button on the [Security tab](https://github.com/karvashish/hardline/security/advisories/new) of this repository. This is the fastest path and keeps the report private until a fix is ready.
2. **Email** — contact the maintainer directly at the address listed on the repository owner's GitHub profile.

When reporting, please include:

- A description of the vulnerability and its impact
- Steps to reproduce, or a proof-of-concept
- The affected Hardline version (`hardline version` output)
- Your assessment of severity, if you have one

You will receive an acknowledgement within a reasonable time — typically a few days. Hardline is currently maintained by a single author, so response times are best-effort and depend on real-world availability. Please do not expect commercial-SLA turnaround.

## Disclosure Timeline

After a report is acknowledged:

1. The maintainer and reporter agree on severity and scope.
2. A fix is developed in a private branch or fork.
3. A coordinated release is planned — typically within 30 days for high-severity issues, longer for lower-severity or research-level findings.
4. The fix is released, a security advisory is published, and credit is given to the reporter unless they request otherwise.

If 90 days pass without a coordinated release and the issue is still unresolved, the reporter is free to disclose publicly. This is a guideline, not a policy — if you need a different timeline, raise it when you report.

## Supported Versions

Hardline is pre-1.0 and under active development. Only the **latest released minor version** receives security fixes. Earlier tagged versions are not patched.

| Version | Supported |
| --- | --- |
| latest minor | yes |
| any earlier tag | no |

Once Hardline reaches 1.0, this table will be updated to reflect a proper support window.

## What Counts As A Security Issue

In scope:

- Any bug that allows an attacker to cause Hardline to execute code, read files, or take actions on a target host beyond what the profile describes
- Any bug that allows an attacker to bypass profile signature verification, manifest integrity, or the rollback conflict check
- Any bug that causes Hardline to leak secrets (private signing keys, SSH private keys, host credentials) in logs, reports, or journals
- Any bug that allows an unprivileged local user on the runner or target to interfere with a running apply or corrupt a rollback journal
- Supply chain concerns in the build or release pipeline that could compromise published artifacts

Out of scope (treat as regular bugs, not vulnerabilities):

- A profile that intentionally performs a dangerous action when applied — that is the profile author's decision, not a Hardline flaw
- Crashes or errors from malformed inputs that result in a refusal to run, with no side effect on the target
- Denial-of-service from an attacker who already has root on the runner or target
- Findings in third-party dependencies that Hardline re-exposes without modification — please report those to the upstream project first; if Hardline's usage amplifies the impact, do report that here
- The documented "plugin: not implemented" behavior on Windows builds — external plugins are unsupported on Windows by design

## Trust Boundaries

Worth stating explicitly, because they shape what counts as a vulnerability:

- **Profiles are trusted if they verify.** A signed profile authored by someone you trust describes work Hardline will perform as root on the target. If the author signs something malicious, Hardline will execute it. Signing attests to authorship, not safety.
- **External plugins are trusted if you place them in the `plugins/` directory.** External `.so` plugins are not signature-verified. They execute with root privileges on the target. Hardline refuses to load them from a world-writable directory, but anything stricter is on you.
- **The runner is trusted.** Anyone with access to the runner's private signing key can sign arbitrary profiles. Anyone who can write to the runner's `plugins/` directory can inject code that runs as root on every target. Protect the runner accordingly.
- **The target's SSH host key is trusted via `known_hosts`.** Hardline refuses to connect to hosts not already in `known_hosts` — it does not perform TOFU.

A vulnerability report that depends on breaking one of these boundaries from outside is in scope. A report that assumes the attacker already controls the runner is not.
