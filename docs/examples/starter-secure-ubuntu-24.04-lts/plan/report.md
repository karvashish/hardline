# Hardline Plan Report

## Profile

- Profile: Starter Secure Ubuntu 24.04 LTS
- Profile ID: `starter-secure-ubuntu-24.04-lts`
- Version: `1.0.0`
- Target: `203.0.113.10` (ubuntu 24.04)

## Summary

- Steps inspected: 23
- Already aligned: 3
- Changes planned: 19
- Needs attention: 1
- Rollback available: true

## Changes Planned

- packages-starter-secure: Update package index; upgrade 11 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- sshd-config-perms: Set metadata on "/etc/ssh/sshd_config" (mode=600 owner=root group=root attrs="")
- ssh-policy: Write the sshd policy to /etc/ssh/sshd_config.d/00-hardline-ssh.conf and reload ssh so it takes effect
- unattended-upgrades-auto: Write rendered configuration from "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- sysctl-hardening-template: Write rendered configuration from "templates/20-sysctl-hardening.conf.tmpl" to "/etc/sysctl.d/99-hardline-hardening.conf" with mode 0644
- sysctl-apply: Restart systemd-sysctl
- firewall-default-deny: Manage nftables table inet filter in "/etc/nftables.d/99-hardline-firewall.nft" (1 policy entries, 6 rules)
- firewall-service-enabled: Enable nftables at boot; ensure nftables is started
- fail2ban-ssh-config: Write rendered configuration from "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- fail2ban-service-enable: Enable fail2ban at boot; ensure fail2ban is started
- auditd-service-enable: Enable auditd at boot; ensure auditd is started
- journald-configure-persistence: Write rendered configuration from "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- journald-reload: Enable systemd-journald at boot; restart systemd-journald
- crontab-perms: Set metadata on "/etc/crontab" (mode=600 owner=root group=root attrs="")
- cron-d-perms: Set metadata on "/etc/cron.d" (mode=700 owner=root group=root attrs="")
- cron-hourly-perms: Set metadata on "/etc/cron.hourly" (mode=700 owner=root group=root attrs="")
- cron-daily-perms: Set metadata on "/etc/cron.daily" (mode=700 owner=root group=root attrs="")
- cron-weekly-perms: Set metadata on "/etc/cron.weekly" (mode=700 owner=root group=root attrs="")
- cron-monthly-perms: Set metadata on "/etc/cron.monthly" (mode=700 owner=root group=root attrs="")

## Needs Attention

- auditd-rules: audit rules watch 1 path(s) that do not exist on this host: /etc/audit; auditctl refuses those rules and the whole load fails with them

## Steps

### packages-starter-secure (`packages_apt`)

- Status: Change planned
- Operator summary: Update package index; upgrade 11 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- Summary: packages step: update package index; upgrade 11 package(s); install: auditd, fail2ban; install 4 dependency package(s); purge: telnet, ftp; autoremove (none currently; may change after upgrade)
- Details:
  - will run: package index update (always)
  - upgrade: would upgrade 11 package(s) (once: packages need to change)
  - package "nftables": currently installed (no install change)
  - package "auditd": not installed (will be installed)
  - package "fail2ban": not installed (will be installed)
  - package "unattended-upgrades": currently installed (no install change)
  - the package manager will also install 4 dependency package(s)
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
  - package "console-setup-linux": installed -> upgraded
  - package "console-setup": installed -> upgraded
  - package "keyboard-configuration": installed -> upgraded
  - package "open-vm-tools": installed -> upgraded
  - package "vim": installed -> upgraded
  - package "vim-common": installed -> upgraded
  - package "vim-tiny": installed -> upgraded
  - package "vim-runtime": installed -> upgraded
  - package "xxd": installed -> upgraded
  - package "wget": installed -> upgraded
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

### ssh-policy (`ssh`)

- Status: Change planned
- Operator summary: Write the sshd policy to /etc/ssh/sshd_config.d/00-hardline-ssh.conf and reload ssh so it takes effect
- Summary: ssh step: write /etc/ssh/sshd_config.d/00-hardline-ssh.conf and reload ssh
- Details:
  - /etc/ssh/sshd_config.d/00-hardline-ssh.conf: will be created with 13 keyword(s)
  - running sshd policy diverges on 6 keyword(s)
  - AllowAgentForwarding: effective value is "yes" but the profile declares "no"
  - AllowTcpForwarding: effective value is "yes" but the profile declares "no"
  - LogLevel: effective value is "INFO" but the profile declares "VERBOSE"
  - MaxAuthTries: effective value is "6" but the profile declares "4"
  - PermitRootLogin: effective value is "without-password" but the profile declares "no"
  - X11Forwarding: effective value is "yes" but the profile declares "no"
- Final state diff:
  - file "/etc/ssh/sshd_config.d/00-hardline-ssh.conf": created -> rendered sshd policy
  - sshd policy: reload ssh to take 6 keyword(s)

### ssh-service-enabled (`service`)

- Status: Already aligned
- Operator summary: Enable ssh at boot
- Summary: service step: enable ssh at boot
- Details:
  - current: enabled=enabled, active=active
  - desired: enabled=enabled, state=unchanged

### unattended-upgrades-auto (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- Summary: template step: render "templates/15-unattended-upgrades.tmpl" to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" (mode 0644)
- Details:
  - destination "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf": does not exist (file will be created)
  - desired: template "templates/15-unattended-upgrades.tmpl" rendered to "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf" with mode 0644
- Final state diff:
  - file "/etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf": absent -> present (mode 644)
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
  - file "/etc/sysctl.d/99-hardline-hardening.conf": absent -> present (mode 644)
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
  - "/etc/nftables.conf": include "include \"/etc/nftables.d/99-hardline-firewall.nft\"" absent; apply will add it
- Final state diff:
  - file "/etc/nftables.d/99-hardline-firewall.nft": absent -> present (mode 644)
  - --- current /etc/nftables.d/99-hardline-firewall.nft (absent)
  - +++ desired /etc/nftables.d/99-hardline-firewall.nft
  - +table inet filter {
  - + chain input {
  - + type filter hook input priority 0;
  - + policy drop;
  - +
  - + iif "lo" accept
  - + ct state invalid drop
  - + ct state established,related accept
  - + tcp dport 22 accept
  - + ip protocol icmp accept
  - + ip6 nexthdr icmpv6 accept
  - + }
  - +}
  - chain input policy: accept -> drop
  - file "/etc/nftables.conf": add include "include \"/etc/nftables.d/99-hardline-firewall.nft\"" (apply will patch)

### firewall-service-enabled (`service`)

- Status: Change planned
- Operator summary: Enable nftables at boot; ensure nftables is started
- Summary: service step: enable nftables at boot; ensure nftables is started
- Details:
  - current: enabled=disabled or not-found, active=inactive or not-found
  - desired: enabled=enabled, state=active
- Final state diff:
  - service enablement: disabled or not-found -> enabled
  - service activity: inactive or not-found -> active

### fail2ban-ssh-config (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- Summary: template step: render "templates/35-fail2ban-ssh-protection.tmpl" to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" (mode 0644)
- Details:
  - destination "/etc/fail2ban/jail.d/99-hardline-ssh.conf": does not exist (file will be created)
  - desired: template "templates/35-fail2ban-ssh-protection.tmpl" rendered to "/etc/fail2ban/jail.d/99-hardline-ssh.conf" with mode 0644
- Final state diff:
  - file "/etc/fail2ban/jail.d/99-hardline-ssh.conf": absent -> present (mode 644)
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

### auditd-service-enable (`service`)

- Status: Change planned
- Operator summary: Enable auditd at boot; ensure auditd is started
- Summary: service step: enable auditd at boot; ensure auditd is started
- Details:
  - current: enabled=disabled or not-found, active=inactive or not-found
  - desired: enabled=enabled, state=active
- Final state diff:
  - service enablement: disabled or not-found -> enabled
  - service activity: inactive or not-found -> active

### auditd-rules (`audit`)

- Status: Needs attention
- Operator summary: Write the audit rules to /etc/audit/rules.d/99-hardline.rules and load them into the running kernel policy
- Summary: audit step: write /etc/audit/rules.d/99-hardline.rules and run augenrules --load
- Details:
  - audit rules watch 1 path(s) that do not exist on this host: /etc/audit; auditctl refuses those rules and the whole load fails with them
  - /etc/audit/rules.d/99-hardline.rules: will be created from "templates/40-audit-hardening-rules.tmpl"
  - running policy is missing 14 rule(s): "-w /etc/audit -p aw -k audit_config", "-w /etc/libaudit.conf -p aw -k audit_config", "-w /etc/passwd -p aw -k identity", "-w /etc/group -p aw -k identity", "-w /etc/shadow -p aw -k identity", "-w /etc/gshadow -p aw -k identity", "-w /etc/security -p aw -k identity", "-w /etc/sudoers -p aw -k privileged", "-w /etc/sudoers.d -p aw -k privileged", "-a always,exit -F arch=b64 -F auid!=unset -F auid>=1000 -S adjtimex -S clock_settime -S settimeofday -k time_change", "-w /etc/localtime -p aw -k time_change", "-a always,exit -F arch=b64 -F auid!=unset -F auid>=1000 -S delete_module -S finit_module -S init_module -k kernel_modules", "-a always,exit -F arch=b64 -F auid!=unset -F auid>=1000 -S setgid -S setregid -S setresgid -S setresuid -S setreuid -S setuid -k priv_change", "-w /var/log/lastlog -p aw -k logins"
- Final state diff:
  - file "/etc/audit/rules.d/99-hardline.rules": created -> rendered audit rules
  - audit policy: augenrules --load would load 14 missing rule(s)
- Highlights:
  - audit rules watch 1 path(s) that do not exist on this host: /etc/audit; auditctl refuses those rules and the whole load fails with them

### journald-configure-persistence (`template`)

- Status: Change planned
- Operator summary: Write rendered configuration from "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- Summary: template step: render "templates/50-journald-hardening.conf.tmpl" to "/etc/systemd/journald.conf.d/99-hardline.conf" (mode 0644)
- Details:
  - destination "/etc/systemd/journald.conf.d/99-hardline.conf": does not exist (file will be created)
  - desired: template "templates/50-journald-hardening.conf.tmpl" rendered to "/etc/systemd/journald.conf.d/99-hardline.conf" with mode 0644
- Final state diff:
  - file "/etc/systemd/journald.conf.d/99-hardline.conf": absent -> present (mode 644)
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
