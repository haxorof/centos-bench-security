#!/bin/env bash

check_5() {
  info "5 - Access, Authentication and Authorization"
  info "5.1     - Configure cron"
  test_wrapper 0 "5.1.1   - Ensure cron daemon is enabled (Scored)" test_service_enabled crond
  test_wrapper 0 "5.1.2   - Ensure permissions on /etc/crontab are configured (Scored)" test_permissions_0600_root_root /etc/crontab
  test_wrapper 0 "5.1.3   - Ensure permissions on /etc/cron.hourly are configured (Scored)" test_permissions_0600_root_root /etc/cron.hourly
  test_wrapper 0 "5.1.4   - Ensure permissions on /etc/cron.daily are configured (Scored)" test_permissions_0600_root_root /etc/cron.daily
  test_wrapper 0 "5.1.5   - Ensure permissions on /etc/cron.weekly are configured (Scored)" test_permissions_0600_root_root /etc/cron.weekly
  test_wrapper 0 "5.1.6   - Ensure permissions on /etc/cron.monthly are configured (Scored)" test_permissions_0600_root_root /etc/cron.monthly
  test_wrapper 0 "5.1.7   - Ensure permissions on /etc/cron.d are configured (Scored)" test_permissions_0600_root_root /etc/cron.d
  test_wrapper 0 "5.1.8   - Ensure at/cron is restricted to authorized users (Scored)" test_at_cron_auth_users
  info "5.2     - SSH Server Configuration"
  test_wrapper 0 "5.2.1   - Ensure permissions on /etc/ssh/sshd_config are configured (Scored)" test_permissions_0600_root_root /etc/ssh/sshd_config
  test_wrapper 0 "5.2.2   - Ensure SSH Protocol is set to 2 (Scored)" test_param "${SSHD_CFG}" Protocol 2
  test_wrapper 0 "5.2.3   - Ensure SSH LogLevel is set to INFO (Scored)" test_param "${SSHD_CFG}" LogLevel INFO
  test_wrapper 0 "5.2.4   - Ensure SSH X11 forwarding is disabled (Scored)" test_param "${SSHD_CFG}" X11Forwarding no
  test_wrapper 0 "5.2.5   - Ensure SSH MaxAuthTries is set to 4 or less (Scored)" test_ssh_param_le MaxAuthTries 4
  test_wrapper 0 "5.2.6   - Ensure SSH IgnoreRhosts is enabled (Scored)" test_param "${SSHD_CFG}" IgnoreRhosts yes
  test_wrapper 0 "5.2.7   - Ensure SSH HostbasedAuthentication is disabled (Scored)" test_param "${SSHD_CFG}" HostbasedAuthentication no
  test_wrapper 0 "5.2.8   - Ensure SSH root login is disabled (Scored)" test_param "${SSHD_CFG}" PermitRootLogin no
  test_wrapper 0 "5.2.9   - Ensure SSH PermitEmptyPasswords is disabled (Scored)" test_param "${SSHD_CFG}" PermitEmptyPasswords no
  test_wrapper 0 "5.2.10  - Ensure SSH PermitUserEnvironment is disabled (Scored)" test_param "${SSHD_CFG}" PermitUserEnvironment no
  todo "5.2.11  - Ensure only approved ciphers are used (Scored)" 
  todo "5.2.12  - Ensure only approved MAC algorithms are used (Scored)"
  test_wrapper 0 "5.2.13  - Ensure SSH Idle Timeout Interval is configured (Scored)" test_ssh_idle_timeout
  test_wrapper 0 "5.2.14  - Ensure SSH LoginGraceTime is set to one minute or less (Scored)" test_ssh_param_le LoginGraceTime 60
  test_wrapper 0 "5.2.15  - Ensure SSH access is limited (Scored)" test_ssh_access
  test_wrapper 0 "5.2.16  - Ensure SSH warning banner is configured (Scored)" test_param "${SSHD_CFG}" Banner /etc/issue.net
  info "5.3     - Configure PAM"
  todo "5.3.1   - Ensure password creation requirements are configured (Scored)"
  todo "5.3.2   - Ensure lockout for failed password attempts is configured (Scored)"
  todo "5.3.3   - Ensure password reuse is limited (Scored)"
  todo "5.3.4   - Ensure password hashing algorithm is SHA-512 (Scored)"
  info "5.4     - User Accounts and Environment"
  info "5.4.1   - Set Shadow Password Suite Parameters"
  todo "5.4.1.1 - Ensure password expiration is 90 days or less (Scored)"
  todo "5.4.1.2 - Ensure minimum days between password changes is 7 or more (Scored)"
  todo "5.4.1.3 - Ensure password expiration warning days is 7 or more (Scored)"
  todo "5.4.1.4 - Ensure inactive password lock is 30 days or less (Scored)"
  todo "5.4.2   - Ensure system accounts are non-login (Scored)"
  todo "5.4.3   - Ensure default group for the root account is GID 0 (Scored)"
  todo "5.4.4   - Ensure default user umask is 027 or more restrictive (Scored)"
  todo "5.5     - Ensure root login is restricted to system console (Not Scored)"
  todo "5.6     - Ensure access to the su command is restricted (Scored)"
}