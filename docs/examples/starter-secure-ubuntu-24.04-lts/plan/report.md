# Hardline Plan Report

## Profile

- Profile: Starter Secure Ubuntu 24.04 LTS
- Profile ID: `starter-secure-ubuntu-24.04-lts`
- Version: `1.0.0`
- Target: `203.0.113.10` (ubuntu 24.04)

## Summary

- Steps inspected: 23
- Already aligned: 2
- Changes planned: 21
- Needs attention: 0
- Rollback available: true

## Changes Planned

- packages-starter-secure: Update package index; upgrade 13 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- sshd-config-perms: Set metadata on "/etc/ssh/sshd_config" (mode=600 owner=root group=root attrs="")
- ssh-template-apply: Write rendered configuration from "templates/10-ssh-sshd-config.tmpl" to "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" with mode 0600
- ssh-service-reload: Enable ssh at boot; reload or restart ssh
- unattended-upgrades-auto: Write rendered configuration from "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- sysctl-hardening-template: Write rendered configuration from "templates/20-sysctl-hardening.conf.tmpl" to "/etc/sysctl.d/99-hardline-hardening.conf" with mode 0644
- sysctl-apply: Restart systemd-sysctl
- firewall-default-deny: Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)
- firewall-service-restart: Enable nftables at boot; restart nftables
- fail2ban-ssh-config: Write rendered configuration from "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- fail2ban-service-enable: Enable fail2ban at boot; ensure fail2ban is started
- auditd-rules-template: Write rendered configuration from "templates/40-audit-hardening-rules.tmpl" to "/etc/audit/rules.d/99-hardline.rules" with mode 0640
- auditd-service-enable: Enable auditd at boot; restart auditd
- journald-configure-persistence: Write rendered configuration from "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- journald-reload: Enable systemd-journald at boot; restart systemd-journald
- crontab-perms: Set metadata on "/etc/crontab" (mode=600 owner=root group=root attrs="")
- cron-d-perms: Set metadata on "/etc/cron.d" (mode=700 owner=root group=root attrs="")
- cron-hourly-perms: Set metadata on "/etc/cron.hourly" (mode=700 owner=root group=root attrs="")
- cron-daily-perms: Set metadata on "/etc/cron.daily" (mode=700 owner=root group=root attrs="")
- cron-weekly-perms: Set metadata on "/etc/cron.weekly" (mode=700 owner=root group=root attrs="")
- cron-monthly-perms: Set metadata on "/etc/cron.monthly" (mode=700 owner=root group=root attrs="")

## Steps

### packages-starter-secure (`packages`)

- Status: Change planned
- Operator summary: Update package index; upgrade 13 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- Summary: packages step: update package index; upgrade 13 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- Details:
  - will run: apt-get update -y (always)
  - upgrade: would upgrade 13 package(s) (once: packages need to change)
  - package "nftables": currently installed (no install change)
  - package "auditd": not installed (will be installed)
  - package "fail2ban": not installed (will be installed)
  - package "unattended-upgrades": currently installed (no install change)
  - apt will also install 4 dependency package(s)
  - package "telnet": currently installed (will be purged)
  - package "rsh-client": not installed (purge has no effect)
  - package "ftp": currently installed (will be purged)
  - package "tftp": not installed (purge has no effect)
  - package "cups": not installed (purge has no effect)
  - package "rpcbind": not installed (purge has no effect)
  - package "nfs-common": not installed (purge has no effect)
  - package "landscape-client": not installed (purge has no effect)
  - autoremove: no packages would be removed (current state; may change after upgrade) (once: packages need to change)
- Final state diff:
  - package index metadata: current -> refreshed from configured repositories
  - package "rsync": installed -> upgraded
  - package "libgcrypt20": installed -> upgraded
  - package "libgnutls30t64": installed -> upgraded
  - package "vim": installed -> upgraded
  - package "vim-common": installed -> upgraded
  - package "vim-tiny": installed -> upgraded
  - package "vim-runtime": installed -> upgraded
  - package "xxd": installed -> upgraded
  - package "bind9-dnsutils": installed -> upgraded
  - package "bind9-host": installed -> upgraded
  - package "bind9-libs": installed -> upgraded
  - package "linux-tools-common": installed -> upgraded
  - package "snapd": installed -> upgraded
  - package "auditd": absent -> installed
  - package "fail2ban": absent -> installed
  - package "libauparse0t64": absent -> installed (dependency)
  - package "python3-pyasyncore": absent -> installed (dependency)
  - package "python3-pyinotify": absent -> installed (dependency)
  - package "whois": absent -> installed (dependency)
  - package "telnet": installed -> purged
  - package "ftp": installed -> purged

### sshd-config-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/ssh/sshd_config" (mode=600 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/ssh/sshd_config"
- Details:
  - current: mode=644 owner=root group=root attrs=""
  - desired: mode=600 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/ssh/sshd_config": 644 -> 600

### ssh-template-apply (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/10-ssh-sshd-config.tmpl" to "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" with mode 0600
- Summary: template step: render "templates/10-ssh-sshd-config.tmpl" to "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" (mode 0600)
- Details:
  - destination "/etc/ssh/sshd_config.d/99-hardline-ssh.conf": does not exist (file will be created)
  - desired: template "templates/10-ssh-sshd-config.tmpl" rendered to "/etc/ssh/sshd_config.d/99-hardline-ssh.conf" with mode 0600
- Final state diff:
  - file "/etc/ssh/sshd_config.d/99-hardline-ssh.conf": absent -> present (mode 0600)
  - --- current /etc/ssh/sshd_config.d/99-hardline-ssh.conf (absent)
  - +++ desired /etc/ssh/sshd_config.d/99-hardline-ssh.conf
  - +Protocol 2
  - +PasswordAuthentication no
  - +PermitRootLogin no
  - +ChallengeResponseAuthentication no
  - +UsePAM yes
  - +X11Forwarding no
  - +AllowTcpForwarding no
  - +AllowAgentForwarding no
  - +LogLevel VERBOSE
  - +MaxAuthTries 4
  - +PubkeyAuthentication yes

### ssh-service-reload (`service`)

- Status: Change planned
- Operator summary: Enable ssh at boot; reload or restart ssh
- Summary: service step: enable ssh at boot; reload or restart ssh
- Details:
  - current: enabled=enabled, active=active
  - desired: enabled=enabled, state=reloaded or restarted (active)
- Final state diff:
  - service: reload-or-restart ssh (currently active)

### unattended-upgrades-auto (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- Summary: template step: render "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" (mode 0644)
- Details:
  - destination "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf": does not exist (file will be created)
  - desired: template "templates/15-unattended-upgrades.tmpl" rendered to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- Final state diff:
  - file "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf": absent -> present (mode 0644)
  - --- current /etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf (absent)
  - +++ desired /etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf
  - +APT::Periodic::Update-Package-Lists "1";
  - +APT::Periodic::Download-Upgradeable-Packages "1";
  - +APT::Periodic::AutocleanInterval "7";
  - +APT::Periodic::Unattended-Upgrade "1";

### sysctl-hardening-template (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/20-sysctl-hardening.conf.tmpl" to "/etc/sysctl.d/99-hardline-hardening.conf" with mode 0644
- Summary: template step: render "templates/20-sysctl-hardening.conf.tmpl" to "/etc/sysctl.d/99-hardline-hardening.conf" (mode 0644)
- Details:
  - destination "/etc/sysctl.d/99-hardline-hardening.conf": does not exist (file will be created)
  - desired: template "templates/20-sysctl-hardening.conf.tmpl" rendered to "/etc/sysctl.d/99-hardline-hardening.conf" with mode 0644
- Final state diff:
  - file "/etc/sysctl.d/99-hardline-hardening.conf": absent -> present (mode 0644)
  - --- current /etc/sysctl.d/99-hardline-hardening.conf (absent)
  - +++ desired /etc/sysctl.d/99-hardline-hardening.conf
  - +net.ipv4.ip_forward = 0
  - +net.ipv4.conf.all.rp_filter = 1
  - +net.ipv4.conf.default.rp_filter = 1
  - +net.ipv4.conf.all.accept_redirects = 0
  - +net.ipv4.conf.default.accept_redirects = 0
  - +net.ipv4.conf.all.secure_redirects = 0
  - +net.ipv4.conf.default.secure_redirects = 0
  - +net.ipv4.icmp_echo_ignore_broadcasts = 1
  - +kernel.kptr_restrict = 2
  - +kernel.dmesg_restrict = 1
  - +fs.protected_hardlinks = 1
  - +fs.protected_symlinks = 1

### sysctl-apply (`service`)

- Status: Change planned
- Operator summary: Restart systemd-sysctl
- Summary: service step: restart systemd-sysctl
- Details:
  - current: enabled=enabled, active=active
  - desired: enabled=unchanged, state=restarted (active)
- Final state diff:
  - service: restart systemd-sysctl (currently active)

### timesyncd-enable (`service`)

- Status: Already aligned
- Operator summary: Enable chrony at boot; ensure chrony is started
- Summary: service step: enable chrony at boot; ensure chrony is started
- Details:
  - current: enabled=enabled, active=active
  - desired: enabled=enabled, state=active

### firewall-default-deny (`firewall`)

- Status: Change planned
- Operator summary: Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)
- Summary: firewall step (deterministic): backend=nftables table=inet filter, managed_dest="/etc/nftables.d/99-hardline-firewall.nft", policies=1, rules=6
- Details:
  - managed destination "/etc/nftables.d/99-hardline-firewall.nft": does not exist (file will be created)
  - desired table: inet filter
  - desired chain policies: 1
  - desired rules: 6
  - current running table: 0 chain policies, 0 managed rules
  - "/etc/nftables.conf": include "include \"/etc/nftables.d/*.nft\"" absent; apply will add it
- Final state diff:
  - file "/etc/nftables.d/99-hardline-firewall.nft": absent -> present (mode 0644)
  - --- current /etc/nftables.d/99-hardline-firewall.nft (absent)
  - +++ desired /etc/nftables.d/99-hardline-firewall.nft
  - +table inet filter {
  - + chain input {
  - + type filter hook input priority 0;
  - + policy drop;
  - +
  - + ip6 nexthdr icmpv6 accept
  - + ip protocol icmp accept
  - + tcp dport 22 accept
  - + iif "lo" accept
  - + ct state established,related accept
  - + ct state invalid drop
  - + }
  - +}
  - chain input policy: accept -> drop
  - file "/etc/nftables.conf": add include "include \"/etc/nftables.d/*.nft\"" (apply will patch)

### firewall-service-restart (`service`)

- Status: Change planned
- Operator summary: Enable nftables at boot; restart nftables
- Summary: service step: enable nftables at boot; restart nftables
- Details:
  - current: enabled=disabled or not-found, active=inactive or not-found
  - desired: enabled=enabled, state=restarted (active)
- Final state diff:
  - service enablement: disabled or not-found -> enabled
  - service: restart nftables (currently inactive or not-found)

### fail2ban-ssh-config (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- Summary: template step: render "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" (mode 0644)
- Details:
  - destination "/etc/fail2ban/jail.d/99-hardline-ssh.conf": does not exist (file will be created)
  - desired: template "templates/35-fail2ban-ssh-protection.tmpl" rendered to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- Final state diff:
  - file "/etc/fail2ban/jail.d/99-hardline-ssh.conf": absent -> present (mode 0644)
  - --- current /etc/fail2ban/jail.d/99-hardline-ssh.conf (absent)
  - +++ desired /etc/fail2ban/jail.d/99-hardline-ssh.conf
  - +[sshd]
  - +enabled = true
  - +maxretry = 5
  - +findtime = 600
  - +bantime = 3600

### fail2ban-service-enable (`service`)

- Status: Change planned
- Operator summary: Enable fail2ban at boot; ensure fail2ban is started
- Summary: service step: enable fail2ban at boot; ensure fail2ban is started
- Details:
  - current: enabled=disabled or not-found, active=inactive or not-found
  - desired: enabled=enabled, state=active
- Final state diff:
  - service enablement: disabled or not-found -> enabled
  - service activity: inactive or not-found -> active

### auditd-rules-template (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/40-audit-hardening-rules.tmpl" to "/etc/audit/rules.d/99-hardline.rules" with mode 0640
- Summary: template step: render "templates/40-audit-hardening-rules.tmpl" to "/etc/audit/rules.d/99-hardline.rules" (mode 0640)
- Details:
  - destination "/etc/audit/rules.d/99-hardline.rules": does not exist (file will be created)
  - desired: template "templates/40-audit-hardening-rules.tmpl" rendered to "/etc/audit/rules.d/99-hardline.rules" with mode 0640
- Final state diff:
  - file "/etc/audit/rules.d/99-hardline.rules": absent -> present (mode 0640)
  - --- current /etc/audit/rules.d/99-hardline.rules (absent)
  - +++ desired /etc/audit/rules.d/99-hardline.rules
  - +## Clear any existing rules
  - +-D
  - +
  - +## Buffer size (keep modest)
  - +-b 8192
  - +## On failure: log but do not hard-stop the box
  - +-f 1
  - +########################
  - +# Audit configuration
  - +-w /etc/audit/ -p wa -k audit_config
  - +-w /etc/libaudit.conf -p wa -k audit_config
  - +-w /etc/audisp/ -p wa -k audit_config
  - +# Identity and access
  - +-w /etc/passwd -p wa -k identity
  - +-w /etc/group -p wa -k identity
  - +-w /etc/shadow -p wa -k identity
  - +-w /etc/gshadow -p wa -k identity
  - +-w /etc/security/ -p wa -k identity
  - +## Sudoers changes
  - +-w /etc/sudoers -p wa -k privileged
  - +-w /etc/sudoers.d/ -p wa -k privileged
  - +# Time changes
  - +-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -F auid>=1000 -F auid!=4294967295 -k time_change
  - +-w /etc/localtime -p wa -k time_change
  - +# Kernel module changes
  - +-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -F auid>=1000 -F auid!=4294967295 -k kernel_modules
  - ... 16 more content diff line(s) omitted

### auditd-service-enable (`service`)

- Status: Change planned
- Operator summary: Enable auditd at boot; restart auditd
- Summary: service step: enable auditd at boot; restart auditd
- Details:
  - current: enabled=disabled or not-found, active=inactive or not-found
  - desired: enabled=enabled, state=restarted (active)
- Final state diff:
  - service enablement: disabled or not-found -> enabled
  - service: restart auditd (currently inactive or not-found)

### journald-configure-persistence (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- Summary: template step: render "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" (mode 0644)
- Details:
  - destination "/etc/systemd/journald.conf.d/99-hardline.conf": does not exist (file will be created)
  - desired: template "templates/50-journald-hardening.conf.tmpl" rendered to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- Final state diff:
  - file "/etc/systemd/journald.conf.d/99-hardline.conf": absent -> present (mode 0644)
  - --- current /etc/systemd/journald.conf.d/99-hardline.conf (absent)
  - +++ desired /etc/systemd/journald.conf.d/99-hardline.conf
  - +[Journal]
  - +Storage=persistent
  - +Compress=yes
  - +SystemMaxUse=512M
  - +SystemKeepFree=50M
  - +MaxRetentionSec=10day
  - +MaxFileSec=1day
  - +RateLimitIntervalSec=30s
  - +RateLimitBurst=2000

### journald-reload (`service`)

- Status: Change planned
- Operator summary: Enable systemd-journald at boot; restart systemd-journald
- Summary: service step: enable systemd-journald at boot; restart systemd-journald
- Details:
  - current: enabled=enabled, active=active
  - desired: enabled=enabled, state=restarted (active)
- Final state diff:
  - service: restart systemd-journald (currently active)

### crontab-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/crontab" (mode=600 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/crontab"
- Details:
  - current: mode=644 owner=root group=root attrs=""
  - desired: mode=600 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/crontab": 644 -> 600

### cron-d-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/cron.d" (mode=700 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/cron.d"
- Details:
  - current: mode=755 owner=root group=root attrs=""
  - desired: mode=700 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/cron.d": 755 -> 700

### cron-hourly-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/cron.hourly" (mode=700 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/cron.hourly"
- Details:
  - current: mode=755 owner=root group=root attrs=""
  - desired: mode=700 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/cron.hourly": 755 -> 700

### cron-daily-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/cron.daily" (mode=700 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/cron.daily"
- Details:
  - current: mode=755 owner=root group=root attrs=""
  - desired: mode=700 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/cron.daily": 755 -> 700

### cron-weekly-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/cron.weekly" (mode=700 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/cron.weekly"
- Details:
  - current: mode=755 owner=root group=root attrs=""
  - desired: mode=700 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/cron.weekly": 755 -> 700

### cron-monthly-perms (`file_meta`)

- Status: Change planned
- Operator summary: Set metadata on "/etc/cron.monthly" (mode=700 owner=root group=root attrs="")
- Summary: file_meta step: re-stamp metadata on "/etc/cron.monthly"
- Details:
  - current: mode=755 owner=root group=root attrs=""
  - desired: mode=700 owner=root group=root attrs=""
- Final state diff:
  - mode "/etc/cron.monthly": 755 -> 700

### grub-cfg-perms (`file_meta`)

- Status: Already aligned
- Operator summary: "/boot/grub/grub.cfg" already has the desired metadata
- Summary: file_meta step: no change required for "/boot/grub/grub.cfg" (metadata already matches)
- Details:
  - current: mode=600 owner=root group=root attrs=""
  - desired: mode=600 owner=root group=root attrs=""

## Next Steps

- Apply changes: `hardline apply starter-secure-ubuntu-24.04-lts --host 203.0.113.10`
- Rollback last run: `hardline rollback starter-secure-ubuntu-24.04-lts --host 203.0.113.10`
- No changes have been made yet.
