#!/bin/env bash

YUM_CONF='/etc/yum.conf'
GRUB_CFG='/boot/grub2/grub.cfg'
GRUB_DIR='/etc/grub.d'
SELINUX_CFG='/etc/selinux/config'
NTP_CONF='/etc/ntp.conf'
SYSCON_NTPD='/etc/sysconfig/ntpd'
NTP_SRV='/usr/lib/systemd/system/ntpd.service'
CHRONY_CONF='/etc/chrony.conf'
CHRONY_SYSCON='/etc/sysconfig/chronyd'
LIMITS_CNF='/etc/security/limits.conf'
SYSCTL_CNF='/etc/sysctl.conf'
CENTOS_REL='/etc/centos-release'
HOSTS_ALLOW='/etc/hosts.allow'
HOSTS_DENY='/etc/hosts.deny'
CIS_CNF='/etc/modprobe.d/CIS.conf'
RSYSLOG_CNF='/etc/rsyslog.conf'
SYSLOGNG_CONF='/etc/syslog-ng/syslog-ng.conf'
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
GDM_PROFILE='/etc/dconf/profile/gdm'
GDM_BANNER_MSG='/etc/dconf/db/gdm.d/01-banner-message'
RESCUE_SRV='/usr/lib/systemd/system/rescue.service'

if [[ "$BENCH_SKIP_SLOW" == "1" ]]; then
  DO_SKIP_SLOW=1
else
  DO_SKIP_SLOW=0
fi

test_module_disabled() {
  local module="${1}"
  modprobe -n -v ${module} 2>&1 | grep -q "install \+/bin/true" || return 
  lsmod | grep -qv "${module}" || return
}

test_separate_partition() {
  local target="${1}"
  findmnt -n ${target} | grep -q "${target}" || return
}

test_mount_option() {
  local target="${1}"
  local mnt_option="${2}"
  findmnt -nlo options ${target} | grep -q "${mnt_option}" || return
}

test_sticky_wrld_w_dirs() {
  local dirs="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \))"
  [[ -z "${dirs}" ]] || return
}

test_service_disable() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>&1 | egrep -q 'disabled|Failed' || return
}

test_service_enabled() {
  local service="$1" 
  systemctl is-enabled "${service}" 2>&1 | grep -q 'enabled' || return
}

test_yum_gpgcheck() {
  if [[ -f ${YUM_CONF} ]]; then
    grep -q ^gpgcheck ${YUM_CONF} 2>/dev/null || return
  fi
  ! grep ^gpgcheck /etc/yum.repos.d/* | grep 0$ || return
}

test_rpm_installed() {
  local rpm="${1}"
  rpm -q ${rpm} | grep -qe "^${rpm}" || return
}

test_rpm_not_installed() {
  local rpm="${1}"
  rpm -q ${rpm} | grep -q "not installed" || return
}

test_aide_cron() {
  crontab -u root -l 2>/dev/null | cut -d\# -f1 | grep -q "aide \+--check" || return
}

test_file_perms() {
  local file="${1}"
  local pattern="${2}"  
  stat -L -c "%a" ${file} | grep -qE "^${pattern}$" || return
}

test_root_owns() {
  local file="${1}"
  stat -L -c "%u %g" ${file} | grep -q '0 0' || return
}

test_grub_permissions() {
  test_root_owns ${GRUB_CFG}
  test_file_perms ${GRUB_CFG} 0600
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

test_sysctl() {
  local flag="$1"
  local value="$2"
  sysctl "${flag}" | cut -d= -f2 | tr -d '[[:space:]]' | grep -q "${value}" || return
}

test_restrict_core_dumps() {
  egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${LIMITS_CNF}" || return
  for f in /etc/security/limits.d/*; do
    egrep -q "\*{1}[[:space:]]+hard[[:space:]]+core[[:space:]]+0" "${f}" || return
  done
  test_sysctl fs.suid_dumpable 0 || return 
}

test_xd_nx_support_enabled() {
  dmesg | egrep -q "NX[[:space:]]\(Execute[[:space:]]Disable\)[[:space:]]protection:[[:space:]]active" || return
}

test_selinux_grubcfg() {
  local grep_out1
  grep_out1="$(grep selinux=0 ${GRUB_CFG})"
  [[ -z "${grep_out1}" ]] || return
  local grep_out2
  grep_out2="$(grep enforcing=0 ${GRUB_CFG})"
  [[ -z "${grep_out2}" ]] || return
}

test_selinux_state() {
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUX=' | tr -d '[[:space:]]' | grep -q 'SELINUX=enforcing' || return
}

test_selinux_policy() {
  cut -d \# -f1 ${SELINUX_CFG} | grep 'SELINUXTYPE=' | tr -d '[[:space:]]' | grep -q 'SELINUXTYPE=targeted' || return
}

test_unconfined_procs() {
  local ps_out
  ps_out="$(ps -eZ | egrep 'initrc|unconfined' | egrep -v 'bash|ps|grep')"
  [[ -n "${ps_out}" ]] || return
}

test_warn_banner() {
  local banner
  banner="$(egrep '(\\v|\\r|\\m|\\s)' ${1})"
  [[ -z "${banner}" ]] || return
}

test_permissions_0644_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 644 || return
}

test_permissions_0600_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 600 || return
}

test_permissions_0000_root_root() {
  local file=$1
  test_root_owns ${file} || return
  test_file_perms ${file} 0 || return
}

test_gdm_banner_msg() {
  if [[ -f "${BANNER_MSG}" ]] ; then
    egrep '[org/gnome/login-screen]' ${BANNER_MSG} || return
    egrep 'banner-message-enable=true' ${BANNER_MSG} || return
    egrep 'banner-message-text=' ${BANNER_MSG} || return
  fi
}

test_gdm_banner() {
  if [[ -f "${GDM_PROFILE}" ]] ; then
    egrep 'user-db:user' ${GDM_PROFILE} || return
    egrep 'system-db:gdm' ${GDM_PROFILE} || return
    egrep 'file-db:/usr/share/gdm/greeter-dconf-defaults' ${GDM_PROFILE} || return
    test_gdm_banner_msg || return
  fi
}

test_yum_check_update() {
  yum -q check-update &>/dev/null || return
}

test_dgram_stream_services_disabled() {
  local service=$1
  test_service_disable ${service}-dgram || return
  test_service_disable ${service}-stream || return
}

test_time_sync_services_enabled() {
  test_service_enabled ntpd && return
  test_service_enabled chronyd && return
  return 1
}

test_ntp_cfg() {
  cut -d\# -f1 ${NTP_CONF} | egrep "restrict{1}[[:space:]]+default{1}" ${NTP_CONF} | grep kod | grep nomodify | grep notrap | grep nopeer | grep -q noquery || return
  cut -d\# -f1 ${NTP_CONF} | egrep "restrict{1}[[:space:]]+\-6{1}[[:space:]]+default" | grep kod | grep nomodify | grep notrap | grep nopeer | grep -q noquery || return
  cut -d\# -f1 ${NTP_CONF} | egrep -q "^[[:space:]]*server" || return
  cut -d\# -f1 ${SYSCON_NTPD} | grep "OPTIONS=" | grep -q "ntp:ntp" && return
  cut -d\# -f1 ${NTP_SRV} | grep "^ExecStart" | grep -q "ntp:ntp" && return
  return 1
}

test_chrony_cfg() {
  cut -d\# -f1 ${CHRONY_CONF} | egrep -q "^[[:space:]]*server" || return
  cut -d\# -f1 ${CHRONY_SYSCON} | grep "OPTIONS=" | grep -q "\-u chrony" || return
}

test_nfs_rpcbind_services_disabled() {
  test_service_disable nfs || return
  test_service_disable rpcbind || return
}

test_mta_local_only() {
  netstat_out="$(netstat -an | grep "LIST" | grep ":25[[:space:]]")"
  if [[ "$?" -eq 0 ]] ; then
    ip=$(echo ${netstat_out} | cut -d: -f1 | cut -d" " -f4)
    [[ "${ip}" = "127.0.0.1" ]] || return    
  fi
}

test_rsh_service_disabled() {
  test_service_disable rsh.socket || return
  test_service_disable rlogin.socket || return
  test_service_disable rexec.socket || return
}

test_net_ipv4_conf_all_default() {
  local suffix=$1
  local value=$2
  test_sysctl "net.ipv4.conf.all.${suffix}" ${value} || return
  test_sysctl "net.ipv4.conf.default.${suffix}" ${value} || return
}

test_net_ipv6_conf_all_default() {
  local suffix=$1
  local value=$2
  test_sysctl "net.ipv6.conf.all.${suffix}" ${value} || return
  test_sysctl "net.ipv6.conf.default.${suffix}" ${value} || return
}

test_ipv6_disabled() {
  modprobe -c | egrep -q '[[:space:]]*options[[:space:]]+ipv6[[:space:]]+disable=1' || return
}

test_tcp_wrappers_installed() {
  test_rpm_installed tcp_wrappers
  test_rpm_installed tcp_wrappers-libs
}

test_hosts_deny_content() {
  cut -d\# -f1 ${HOSTS_DENY} | grep -q "ALL[[:space:]]*:[[:space:]]*ALL" || return
}

test_firewall_policy() {
  iptables -L | egrep -q "Chain[[:space:]]+INPUT[[:space:]]+" | egrep -q "policy[[:space:]]+DROP" || return
  iptables -L | egrep -q "Chain[[:space:]]+FORWARD[[:space:]]+" | egrep -q "policy[[:space:]]+DROP" || return
  iptables -L | egrep -q "Chain[[:space:]]+OUTPUT[[:space:]]+" | egrep -q "policy[[:space:]]+DROP" || return
}

test_loopback_traffic_conf() {
  local accept="ACCEPT[[:space:]]+all[[:space:]]+--[[:space:]]+lo[[:space:]]+\*[[:space:]]+0\.0\.0\.0\/0[[:space:]]+0\.0\.0\.0\/0"
  local drop="DROP[[:space:]]+all[[:space:]]+--[[:space:]]+\*[[:space:]]+\*[[:space:]]+127\.0\.0\.0\/8[[:space:]]+0\.0\.0\.0\/0"
  iptables -L INPUT -v -n | egrep -q ${accept} || return
  iptables -L INPUT -v -n | egrep -q ${drop} || return
  iptables -L OUTPUT -v -n | egrep -q ${accept} || return
}

test_wireless_if_disabled() {
  for i in $(iwconfig 2>&1 | egrep -v "no[[:space:]]*wireless" | cut -d' ' -f1); do
    ip link show up | grep "${i}:"
    if [[ "$?" -eq 0 ]]; then
    return 1
    fi
  done
}

test_audit_log_storage_size() {
  cut -d\# -f1 ${AUDITD_CNF} | egrep -q "max_log_file[[:space:]]|max_log_file=" || return
}

test_dis_on_audit_log_full() {
  cut -d\# -f2 ${AUDITD_CNF} | grep 'space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'email' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'action_mail_acct' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'root' || return
  cut -d\# -f2 ${AUDITD_CNF} | grep 'admin_space_left_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'halt' || return
}

test_keep_all_audit_info() {
  cut -d\# -f2 ${AUDITD_CNF} | grep 'max_log_file_action' | cut -d= -f2 | tr -d '[[:space:]]' | grep -q 'keep_logs' || return
}

test_audit_procs_prior_2_auditd() {
  grep_grub="$(grep "^[[:space:]]*linux" ${GRUB_CFG} | grep -v 'audit=1')"
  [[ -z "${grep_grub}" ]] || return
}

test_audit_date_time() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-S[[:space:]]+settimeofday" \
  | egrep "\-S[[:space:]]+adjtimex" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+stime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-S[[:space:]]+clock_settime" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+time-change" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/localtime" || return
}

test_audit_user_group() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/group" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/passwd" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/gshadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/shadow" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+identity" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/security\/opasswd" || return
}

test_audit_network_env() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b64" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-S[[:space:]]+sethostname" \
  | egrep "\-S[[:space:]]+setdomainname" | egrep "\-F[[:space:]]+arch=b32" | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/issue.net" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/hosts" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+system-locale" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sysconfig\/network" || return
}

test_audit_sys_mac() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+MAC-policy" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/selinux\/" || return
}

test_audit_logins_logouts() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/faillog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/lastlog" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+logins" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/tallylog" || return
}

test_audit_session_init() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/run\/utmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/wtmp" || return
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+session" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/btmp" || return
}

test_audit_dac_perm_mod_events() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chmod" \
  | egrep "\-S[[:space:]]+fchmod" | egrep "\-S[[:space:]]+fchmodat" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+chown" \
  | egrep "\-S[[:space:]]+fchown" | egrep "\-S[[:space:]]+fchownat" | egrep "\-S[[:space:]]+fchown" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b64" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+perm_mod" | egrep "\-S[[:space:]]+setxattr" \
  | egrep "\-S[[:space:]]+lsetxattr" | egrep "\-S[[:space:]]+fsetxattr" | egrep "\-S[[:space:]]+removexattr" \
  | egrep "\-S[[:space:]]+lremovexattr" | egrep "\-S[[:space:]]+fremovexattr" | egrep "\-F[[:space:]]+arch=b32" \
  | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_unsuc_unauth_acc_attempts() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EACCES" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+access" | egrep "\-S[[:space:]]+creat" \
  | egrep "\-S[[:space:]]+open" | egrep "\-S[[:space:]]+openat" | egrep "\-S[[:space:]]+truncate" \
  | egrep "\-S[[:space:]]+ftruncate" | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" | egrep "\-F[[:space:]]exit=\-EPERM" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

test_coll_priv_cmds() {
  local priv_cmds
  priv_cmds="$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f)"
  for cmd in ${priv_cmds} ; do
    cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+privileged" | egrep "\-F[[:space:]]+path=${cmd}" \
    | egrep "\-F[[:space:]]+perm=x" | egrep "\-F[[:space:]]+auid>=1000" | egrep "\-F[[:space:]]+auid\!=4294967295" \
    | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
  done
}

test_coll_suc_fs_mnts() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+mounts" | egrep "\-S[[:space:]]+mount" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_coll_file_del_events() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+delete" | egrep "\-S[[:space:]]+unlink" \
  | egrep "\-F[[:space:]]+arch=b32" | egrep "\-S[[:space:]]+unlinkat" | egrep "\-S[[:space:]]+rename" \
  | egrep "\-S[[:space:]]+renameat" | egrep "\-F[[:space:]]+auid>=1000" \
  | egrep "\-F[[:space:]]+auid\!=4294967295" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return

}

test_coll_chg2_sysadm_scope() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+scope" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/etc\/sudoers" || return

}

test_coll_sysadm_actions() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+actions" | egrep "\-p[[:space:]]+wa" \
  | egrep -q "\-w[[:space:]]+\/var\/log\/sudo.log" || return
}

test_kmod_lod_unlod() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/insmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/rmmod" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-p[[:space:]]+x" \
  | egrep -q "\-w[[:space:]]+\/sbin\/modprobe" || return

  cut -d\# -f1 ${AUDIT_RULES} | egrep "\-k[[:space:]]+modules" | egrep "\-S[[:space:]]+delete_module" \
  | egrep "\-F[[:space:]]+arch=b64" | egrep "\-S[[:space:]]+init_module" \
  | egrep -q "\-a[[:space:]]+always,exit|\-a[[:space:]]+exit,always" || return
}

test_audit_cfg_immut() {
  cut -d\# -f1 ${AUDIT_RULES} | egrep -q "^-e[[:space:]]+2" || return
}

test_rsyslog_content() {
  grep -q "^*.*[^I][^I]*@" ${RSYSLOG_CNF} 2>/dev/null || return
}

test_syslogng_content() {
  egrep -q "destination[[:space:]]+logserver[[:space:]]+\{[[:space:]]*tcp\(\".+\"[[:space:]]+port\([[:digit:]]+\)\)\;[[:space:]]*\}\;" ${SYSLOGNG_CONF} 2>/dev/null || return
  egrep -q "log[[:space:]]+\{[[:space:]]*source\(src\)\;[[:space:]]*destination\(logserver\)\;[[:space:]]*\}\;" ${SYSLOGNG_CONF} 2>/dev/null || return
}

test_rsyslog_syslogng_installed() {
  test_rpm_installed rsyslog && return
  test_rpm_installed syslog-ng && return
  return 1
}

test_var_log_files_permissions() {
  [[ $(find /var/log -type f -ls | grep -v "\-r\-\-\-\-\-\-\-\-" | grep -v "\-rw\-\-\-\-\-\-\-" | grep -v "\-rw\-r\-\-\-\-\-" | wc -l) -eq 0 ]] || return
}

test_at_cron_auth_users() {
  [[ ! -f ${AT_DENY} ]] || return 
  [[ ! -f ${CRON_DENY} ]] || return 
  test_permissions_0600_root_root "${CRON_ALLOW}" || return
  test_permissions_0600_root_root "${AT_ALLOW}" || return
}

test_param() {
  local file="${1}" 
  local parameter="${2}" 
  local value="${3}" 
  cut -d\# -f1 ${file} | egrep -q "^${parameter}[[:space:]]+${value}" || return
}

test_ssh_param_le() {
  local parameter="${1}" 
  local allowed_max="${2}"
  local actual_value
  actual_value=$(cut -d\# -f1 ${SSHD_CFG} | grep "${parameter}" | cut -d" " -f2)
  [[ ${actual_value} -le ${allowed_max} ]] || return 
}

test_ssh_idle_timeout() {
  test_ssh_param_le ClientAliveInterval 300 || return
  test_ssh_param_le ClientAliveCountMax 3 || return
}

test_ssh_access() {
  local allow_users
  local allow_groups
  local deny_users
  local deny_users
  allow_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowUsers" | cut -d" " -f2)"
  allow_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "AllowGroups" | cut -d" " -f2)"
  deny_users="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyUsers" | cut -d" " -f2)"
  deny_groups="$(cut -d\# -f1 ${SSHD_CFG} | grep "DenyGroups" | cut -d" " -f2)"
  [[ -n "${allow_users}" ]] || return
  [[ -n "${allow_groups}" ]] || return
  [[ -n "${deny_users}" ]] || return
  [[ -n "${deny_groups}" ]] || return
}

test_wrapper() {
  local do_skip=$1
  shift
  local msg=$1
  shift
  local func=$1
  shift
  local args=$@
  if [[ "$do_skip" -eq 0 ]]; then
    ${func} ${args} 
    if [[ "$?" -eq 0 ]]; then
      pass "${msg}"
    else
      warn "${msg}"
    fi
  else
    skip "${msg}"
  fi
}
