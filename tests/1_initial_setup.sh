#!/bin/env bash

check_1() {
  info "1 - Initial Setup"
  info "1.1     - Filesystem Configuration"
  info "1.1.1   - Disable unused filesystems"
  test_wrapper 0 "1.1.1.1 - Ensure mounting of cramfs filesystems is disabled (Scored)" test_module_disabled cramfs
  test_wrapper 0 "1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled (Scored)" test_module_disabled freevxfs
  test_wrapper 0 "1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled (Scored)" test_module_disabled jffs2
  test_wrapper 0 "1.1.1.4 - Ensure mounting of hfs filesystems is disabled (Scored)" test_module_disabled hfs
  test_wrapper 0 "1.1.1.5 - Ensure mounting of hfsplus filesystems is disabled (Scored)" test_module_disabled hfsplus
  test_wrapper 0 "1.1.1.6 - Ensure mounting of squashfs filesystems is disabled (Scored)" test_module_disabled squashfs
  test_wrapper 0 "1.1.1.7 - Ensure mounting of udf filesystems is disabled (Scored)" test_module_disabled udf
  test_wrapper 0 "1.1.1.8 - Ensure mounting of FAT filesystems is disabled (Scored)" test_module_disabled vfat

  test_wrapper 0 "1.1.2   - Ensure separate partition exists for /tmp (Scored)" test_separate_partition /tmp
  test_wrapper 0 "1.1.3   - Ensure nodev option set on /tmp partition (Scored)" test_mount_option /tmp nodev
  test_wrapper 0 "1.1.4   - Ensure nosuid option set on /tmp partition (Scored)" test_mount_option /tmp nosuid
  test_wrapper 0 "1.1.5   - Ensure noexec option set on /tmp partition (Scored)" test_mount_option /tmp noexec
  test_wrapper 0 "1.1.6   - Ensure separate partition exists for /var (Scored)" test_separate_partition /var
  test_wrapper 0 "1.1.7   - Ensure separate partition exists for /var/tmp (Scored)" test_separate_partition /var/tmp
  test_wrapper 0 "1.1.8   - Ensure nodev option set on /var/tmp partition (Scored)" test_mount_option /var/tmp nodev
  test_wrapper 0 "1.1.9   - Ensure nosuid option set on /var/tmp partition (Scored)" test_mount_option /var/tmp nosuid
  test_wrapper 0 "1.1.10  - Ensure noexec option set on /var/tmp partition (Scored)" test_mount_option /var/tmp noexec
  test_wrapper 0 "1.1.11  - Ensure separate partition exists for /var/log (Scored)" test_separate_partition /var/log
  test_wrapper 0 "1.1.12  - Ensure separate partition exists for /var/log/audit (Scored)" test_separate_partition /var/log/audit
  test_wrapper 0 "1.1.13  - Ensure separate partition exists for /home (Scored)" test_separate_partition /home
  test_wrapper 0 "1.1.14  - Ensure nodev option set on /home partition (Scored)" test_mount_option /home nodev
  test_wrapper 0 "1.1.15  - Ensure nodev option set on /dev/shm partition (Scored)" test_mount_option /dev/shm nodev
  test_wrapper 0 "1.1.16  - Ensure nosuid option set on /dev/shm partition (Scored)" test_mount_option /dev/shm nosuid
  test_wrapper 0 "1.1.17  - Ensure noexec option set on /dev/shm partition (Scored)" test_mount_option /dev/shm noexec
  todo "1.1.18  - Ensure nodev option set on removable media partitions (Not Scored)"
  todo "1.1.19  - Ensure nosuid option set on removable media partitions (Not Scored)"
  todo "1.1.20  - Ensure noexec option set on removable media partitions (Not Scored)"
  test_wrapper $DO_SKIP_SLOW "1.1.21  - Ensure sticky bit is set on all world-writable directories (Scored)" test_sticky_wrld_w_dirs
  test_wrapper 0 "1.1.22  - Disable Automounting (Scored)" test_service_disable autofs

  info "1.2     - Configure Software Updates"
  info "1.2.1   - Ensure package manager repositories are configured (Not Scored)"
  info "1.2.2   - Ensure GPG keys are configured (Not Scored)"
  test_wrapper 0 "1.2.3   - Ensure gpgcheck is globally activated (Scored)" test_yum_gpgcheck

  info "1.3     - Filesystem Integrity Checking"
  test_wrapper 0 "1.3.1   - Ensure AIDE is installed (Scored)" test_rpm_installed aide
  test_wrapper 0 "1.3.2   - Ensure filesystem integrity is regularly checked (Scored)" test_aide_cron

  info "1.4     - Secure Boot Settings"
  test_wrapper 0 "1.4.1   - Ensure permissions on bootloader config are configured (Scored)" test_grub_permissions
  test_wrapper 0 "1.4.2   - Ensure bootloader password is set (Scored)" test_boot_pass
  test_wrapper 0 "1.4.3   - Ensure authentication required for single user mode (Not Scored)" test_auth_rescue_mode

  info "1.5     - Additional Process Hardening"
  test_wrapper 0 "1.5.1   - Ensure core dumps are restricted (Scored)" test_restrict_core_dumps
  test_wrapper 0 "1.5.2   - Ensure XD/NX support is enabled (Not Scored)" test_xd_nx_support_enabled
  test_wrapper 0 "1.5.3   - Ensure address space layout randomization (ASLR) is enabled (Scored)" test_sysctl kernel.randomize_va_space 2
  test_wrapper 0 "1.5.4   - Ensure prelink is disabled (Scored)" test_rpm_not_installed prelink

  info "1.6     - Mandatory Access Control"
  test_rpm_installed libselinux
  local do_skip_selinux=$?
  info "1.6.1   - Configure SELinux"
  test_wrapper $do_skip_selinux "1.6.1.1 - Ensure SELinux is not disabled in bootloader configuration (Scored)" test_selinux_grubcfg
  test_wrapper $do_skip_selinux "1.6.1.2 - Ensure the SELinux state is enforcing (Scored)" test_selinux_state
  test_wrapper $do_skip_selinux "1.6.1.3 - Ensure SELinux policy is configured (Scored)" test_selinux_policy
  test_wrapper $do_skip_selinux "1.6.1.4 - Ensure SETroubleshoot is not installed (Scored)" test_rpm_not_installed setroubleshoot
  test_wrapper $do_skip_selinux "1.6.1.5 - Ensure the MCS Translation Service (mcstrans) is not installed (Scored)" test_rpm_not_installed mcstrans
  test_wrapper $do_skip_selinux "1.6.1.6 - Ensure no unconfined daemons exist (Scored)" test_unconfined_procs
  test_wrapper 0 "1.6.2   - Ensure SELinux is installed (Scored)" test_rpm_installed libselinux

  info "1.7     - Warning Banners"
  info "1.7.1   - Command Line Warning Banners"
  test_wrapper 0 "1.7.1.1 - Ensure message of the day is configured properly (Scored)" test_warn_banner ${MOTD}
  test_wrapper 0 "1.7.1.2 - Ensure local login warning banner is configured properly (Not Scored)" test_warn_banner ${ISSUE}
  test_wrapper 0 "1.7.1.3 - Ensure remote login warning banner is configured properly (Not Scored)" test_warn_banner ${ISSUE_NET}
  test_wrapper 0 "1.7.1.4 - Ensure permissions on /etc/motd are configured (Not Scored)" test_permissions_0644_root_root ${MOTD}
  test_wrapper 0 "1.7.1.5 - Ensure permissions on /etc/issue are configured (Scored)" test_permissions_0644_root_root ${ISSUE}
  test_wrapper 0 "1.7.1.6 - Ensure permissions on /etc/issue.net are configured (Not Scored)" test_permissions_0644_root_root ${ISSUE_NET}
  test_wrapper 0 "1.7.2   - Ensure GDM login banner is configured (Scored)" test_gdm_banner

  test_wrapper $DO_SKIP_SLOW "1.8     - Ensure updates, patches, and additional security software are installed (Not Scored)" test_yum_check_update
}