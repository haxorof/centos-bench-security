#!/bin/env bash

FSTAB='/etc/fstab'
YUM_CONF='/etc/yum.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_DIR='/etc/grub.d'
SELINUX_CFG='/etc/selinux/config'
NTP_CONF='/etc/ntp.conf'
SYSCON_NTPD='/etc/sysconfig/ntpd'
LIMITS_CNF='/etc/security/limits.conf'
SYSCTL_CNF='/etc/sysctl.conf'
CENTOS_REL='/etc/centos-release'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
AUDITD_CNF='/etc/audit/auditd.conf'
AUDIT_RULES='/etc/audit/audit.rules'
LOGR_SYSLOG='/etc/logrotate.d/syslog'
ANACRONTAB='/etc/anacrontab'
CRONTAB='/etc/crontab'
CRON_HOURLY='/etc/cron.hourly'
CRON_DAILY='/etc/cron.daily'
CRON_WEEKLY='/etc/cron.weekly'
CRON_MONTHLY='/etc/cron.monthly'
CRON_DIR='/etc/cron.d'
AT_ALLOW='/etc/at.allow'
AT_DENY='/etc/at.deny'
CRON_ALLOW='/etc/cron.allow'
CRON_DENY='/etc/cron.deny'
SSHD_CFG='/etc/ssh/sshd_config'
SYSTEM_AUTH='/etc/pam.d/system-auth'
PWQUAL_CNF='/etc/security/pwquality.conf'
PASS_AUTH='/etc/pam.d/password-auth'
PAM_SU='/etc/pam.d/su'
GROUP='/etc/group'
LOGIN_DEFS='/etc/login.defs'
PASSWD='/etc/passwd'
SHADOW='/etc/shadow'
GSHADOW='/etc/gshadow'
BASHRC='/etc/bashrc'
PROF_D='/etc/profile.d'
MOTD='/etc/motd'
ISSUE='/etc/issue'
ISSUE_NET='/etc/issue.net'
BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'
RESCUE_SRV='/usr/lib/systemd/system/rescue.service'

test_disable_mounting() {
  local module="${1}"
  modprobe -n -v ${module} 2>&1 | grep -q "install \+/bin/true" || return 
  lsmod | grep -qv "${module}" || return
}

test_separate_partition() {
  local filesystem="${1}"
  grep -q "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" || return
}

test_mount_option() {
  local filesystem="${1}"
  local mnt_option="${2}"
  grep "[[:space:]]${filesystem}[[:space:]]" "${FSTAB}" | grep -q "${mnt_option}" || return
  mount | grep "[[:space:]]${filesystem}[[:space:]]" | grep -q "${mnt_option}" || return
}

test_sticky_wrld_w_dirs() {
  local dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \))"
  [[ -z "${dirs}" ]] || return
}

test_service_disable() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>/dev/null | grep -q 'disabled' && return
}

test_service_enabled() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>/dev/null | grep -q 'enabled' && return
}

test_yum_gpgcheck() {
  if [[ -f ${YUM_CONF} ]]; then
    grep -q ^gpgcheck ${YUM_CONF} 2>/dev/null || return
  fi
  ! grep ^gpgcheck /etc/yum.repos.d/* | grep 0$ || return
}

rpm_installed() {
  local rpm="${1}"
  local rpm_out
  rpm_out="$(rpm -q --queryformat "%{NAME}\n" ${rpm})"
  [[ "${rpm}" = "${rpm_out}" ]] || return
}

verify_aide_cron() {
  crontab -u root -l 2>/dev/null | cut -d\# -f1 | grep -q "aide \+--check" || return
}

test_grub_owns() {
  stat -L -c "%u %g" ${GRUB_CFG} | grep -q '0 0' || return
}

test_boot_pass() {
  grep -q 'set superusers=' "${GRUB_CFG}"
  if [[ "$?" -ne 0 ]]; then
    grep -q 'set superusers=' ${GRUB_DIR}/* || return
    file="$(grep 'set superusers' ${GRUB_DIR}/* | cut -d: -f1)"
    grep -q 'password' "${file}" || return
  else
    grep -q 'password' "${GRUB_CFG}" || return
  fi
}

test_auth_rescue_mode() {
  grep -q /sbin/sulogin ${RESCUE_SRV} || return
}

test_restrict_core_dumps() {
  egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${LIMITS_CNF}" || return
  for f in /etc/security/limits.d/*; do
    egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${f}" || return
  done
  cut -d\# -f1 ${SYSCTL_CNF} | grep fs.suid_dumpable | cut -d= -f2 | tr -d '[[:space:]]' | grep -q '0' || return 
}
test_wrapper() {
  local msg=$1
  shift
  local func=$1
  shift
  local args=$@
  ${func} ${args} 
  #2>/dev/null
  if [[ "$?" -eq 0 ]]; then
    pass "${msg}"
  else
    warn "${msg}"
  fi
}