#!/usr/bin/env bash
# =============================================================================
# os.sh — per-target-OS facts for the integration suite
# =============================================================================
# Sourced by itest.sh. Do not run directly.
#
# The engine carries no distribution knowledge, so the suite cannot either: the
# package plugin, the nftables main config, the sshd unit name and the starter
# profile all come from here, selected by ITEST_OS (or the terraform output).
#
# PKG_PLUGIN is what a generated profile names in its steps. PKG_BACKEND is a
# separate fact: how the suite itself installs and purges packages over SSH when
# it is setting up or asserting state, which is not something a profile says.
#
#   ubuntu  apt    the default target; the Ubuntu starter profile
#   rocky   dnf4   RHEL-family target; the Rocky starter profile
#   fedora  dnf5   dnf5 verification vehicle only; no starter profile

itest_os_init() {
  ITEST_OS="${ITEST_OS:-$(jq -r '.os.value // "ubuntu"' "${OUTPUTS_JSON}")}"

  case "${ITEST_OS}" in
    ubuntu)
      OS_FAMILY="ubuntu"; OS_VERSION="24.04"; OS_VARIANT="lts"
      PKG_BACKEND="apt"; PKG_PLUGIN="packages_apt"
      NFT_MAIN_CONFIG="/etc/nftables.conf"
      SSH_UNIT="ssh"
      TIMESYNC_UNIT="chrony"
      CRON_UNIT="cron"
      AUDIT_PKG="auditd"
      BASE_PROFILE="${ROOT_DIR}/profiles/starter-secure-ubuntu-24.04-lts"
      BASE_PROFILE_ID="starter-secure-ubuntu-24.04-lts"
      BASE_FILE_CHECKS=(
        "etc/ssh/sshd_config.d/00-hardline-ssh.conf|templates/10-ssh-sshd-config.tmpl|600"
        "etc/apt/apt.conf.d/99-hardline-auto-upgrades.conf|templates/15-unattended-upgrades.tmpl|644"
        "etc/sysctl.d/99-hardline-hardening.conf|templates/20-sysctl-hardening.conf.tmpl|644"
        "etc/fail2ban/jail.d/99-hardline-ssh.conf|templates/35-fail2ban-ssh-protection.tmpl|644"
        "etc/audit/rules.d/99-hardline.rules|templates/40-audit-hardening-rules.tmpl|640"
        "etc/systemd/journald.conf.d/99-hardline.conf|templates/50-journald-hardening.conf.tmpl|644"
      )
      BASE_PKGS_PRESENT=(nftables auditd fail2ban unattended-upgrades)
      BASE_PKGS_ABSENT=(telnet rsh-client ftp tftp cups rpcbind nfs-common snapd whoopsie apport landscape-client)
      BASE_UNITS_RUNNING=(ssh chrony nftables fail2ban auditd)
      BASE_TIMERS_ENABLED=(apt-daily-upgrade.timer)
      ;;
    rocky)
      OS_FAMILY="rocky"; OS_VERSION="9"; OS_VARIANT="server"
      PKG_BACKEND="dnf4"; PKG_PLUGIN="packages_dnf4"
      NFT_MAIN_CONFIG="/etc/sysconfig/nftables.conf"
      SSH_UNIT="sshd"
      TIMESYNC_UNIT="chronyd"
      CRON_UNIT="crond"
      AUDIT_PKG="audit"
      BASE_PROFILE="${ROOT_DIR}/profiles/starter-secure-rocky-9"
      BASE_PROFILE_ID="starter-secure-rocky-9"
      BASE_FILE_CHECKS=(
        "etc/ssh/sshd_config.d/00-hardline-ssh.conf|templates/10-ssh-sshd-config.tmpl|600"
        "etc/sysctl.d/99-hardline-hardening.conf|templates/20-sysctl-hardening.conf.tmpl|644"
        "etc/audit/rules.d/99-hardline.rules|templates/40-audit-hardening-rules.tmpl|640"
        "etc/systemd/journald.conf.d/99-hardline.conf|templates/50-journald-hardening.conf.tmpl|644"
      )
      BASE_PKGS_PRESENT=(nftables audit dnf-automatic)
      BASE_PKGS_ABSENT=(telnet rsh ftp tftp cups rpcbind nfs-utils)
      BASE_UNITS_RUNNING=(sshd chronyd nftables auditd)
      # The plain dnf-automatic.timer only downloads unless automatic.conf
      # sets apply_updates, so the profile enables the install timer.
      BASE_TIMERS_ENABLED=(dnf-automatic-install.timer)
      ;;
    fedora)
      OS_FAMILY="fedora"; OS_VERSION="44"; OS_VARIANT="cloud"
      PKG_BACKEND="dnf5"; PKG_PLUGIN="packages_dnf5"
      NFT_MAIN_CONFIG="/etc/sysconfig/nftables.conf"
      SSH_UNIT="sshd"
      TIMESYNC_UNIT="chronyd"
      CRON_UNIT="crond"
      AUDIT_PKG="audit"
      # dnf5 is verified through the dynamic fixtures; no starter profile ships
      # for Fedora, so the base-profile scenario skips itself.
      BASE_PROFILE=""
      BASE_PROFILE_ID=""
      BASE_FILE_CHECKS=()
      BASE_PKGS_PRESENT=()
      BASE_PKGS_ABSENT=()
      BASE_UNITS_RUNNING=()
      BASE_TIMERS_ENABLED=()
      ;;
    *)
      fail "unsupported ITEST_OS ${ITEST_OS} (use ubuntu, rocky, or fedora)"
      ;;
  esac

  echo "itest target: os=${ITEST_OS} plugin=${PKG_PLUGIN} main_config=${NFT_MAIN_CONFIG} ssh_unit=${SSH_UNIT}"
}

# pkg_installed_test prints a remote shell test for an installed package. It is
# printed rather than run so it can be embedded in a batched remote script.
pkg_installed_test() {
  case "${PKG_BACKEND}" in
    apt) printf "dpkg -s '%s' >/dev/null 2>&1" "$1" ;;
    *)   printf "rpm -q '%s' >/dev/null 2>&1" "$1" ;;
  esac
}

pkg_absent_test() {
  printf '! %s' "$(pkg_installed_test "$1")"
}

# pkg_installed queries the host directly; use it for setup assertions.
pkg_installed() {
  ssh_cmd "$(pkg_installed_test "$1")"
}

pkg_install() {
  case "${PKG_BACKEND}" in
    apt) ssh_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y '$1' >/dev/null 2>&1" ;;
    *)   ssh_cmd "sudo dnf -y install '$1' >/dev/null 2>&1" ;;
  esac
}

pkg_purge() {
  case "${PKG_BACKEND}" in
    apt) ssh_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y '$1' >/dev/null 2>&1" ;;
    *)   ssh_cmd "sudo dnf -y remove '$1' >/dev/null 2>&1" ;;
  esac
}

# nft_include_test prints the remote check that the managed include is wired
# into whichever main config this family uses.
nft_include_test() {
  printf "grep -E -q 'include[[:space:]]+\"?/etc/nftables\\\\.d/\\\\*\\\\.nft\"?' %s" "${NFT_MAIN_CONFIG}"
}

# Scenarios that apply a firewall need the nftables include the starter profile
# writes, so they can only run where a starter profile ships.
guard_base_profile() {
  if [ -z "${BASE_PROFILE}" ]; then
    scenario_skip "no starter profile ships for ITEST_OS=${ITEST_OS}"
    return 1
  fi
  return 0
}
